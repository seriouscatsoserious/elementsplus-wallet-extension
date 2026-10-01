//! Minimal MCP server (protocol 2025-06-18) over stdio: newline-delimited
//! JSON-RPC 2.0 with `initialize`, `ping`, `tools/list` and `tools/call`.
//!
//! Tool failures (including policy refusals) are returned as tool results
//! with `isError: true`; protocol problems are JSON-RPC errors. No tool can
//! reveal the mnemonic or keystore: the backend has no such operation.

use std::io::{BufRead, Write};

use anyhow::{anyhow, bail, Result};
use serde_json::{json, Value};

use crate::wallet::{error_json, Exec, Wallet};

pub const PROTOCOL_VERSION: &str = "2025-06-18";

/// What the MCP layer needs from a wallet. Tests use a fake.
pub trait Backend {
    fn call_tool(&self, name: &str, args: &Value) -> Result<Value>;
}

const AMOUNT: &str = "Decimal amount in the asset's precision (e.g. \"1.5\"; ECX has 8 decimals, unknown assets 0) or \"atomic:<n>\" for raw units.";
const ASSET: &str = "Asset: 64-hex asset id, or the ticker of a locally verified asset (\"ECX\" = policy asset). Tickers must be unique.";

fn s(description: &str) -> Value {
    json!({ "type": "string", "description": description })
}

fn object(properties: Value, required: &[&str]) -> Value {
    json!({
        "type": "object",
        "properties": properties,
        "required": required,
        "additionalProperties": false,
    })
}

const MUTATING_NOTE: &str = " Signs only if policy.toml allows it. In confirm mode the request is NOT signed: the result has status \"approval_required\", the review, an approval_hash and an approve_command for the human to run. Result statuses: completed | approval_required; policy refusals are errors with the decision attached.";

/// Tool definitions with JSON Schemas.
pub fn tools() -> Vec<Value> {
    let read_only = json!({ "readOnlyHint": true, "openWorldHint": true });
    let mutating = json!({ "readOnlyHint": false, "destructiveHint": true, "openWorldHint": true });
    let fee_rate = json!({ "type": "integer", "minimum": 1, "maximum": 1000, "description": "Fee rate in sat/vB (default from config)." });
    let side = json!({ "type": "string", "enum": ["exact_in", "exact_out"], "description": "exact_in (default): amount is what you sell. exact_out: amount is what you buy." });
    let result = json!({ "type": "object" });
    let tool = |name: &str, title: &str, description: String, input: Value, annotations: &Value| {
        json!({
            "name": name,
            "title": title,
            "description": description,
            "inputSchema": input,
            "outputSchema": result,
            "annotations": annotations,
        })
    };
    vec![
        tool("get_address", "Receive address", "Next unused receive address of this wallet (explicit P2WPKH).".into(), object(json!({}), &[]), &read_only),
        tool("get_balances", "Balances", "Per-asset balances from locally verified UTXOs (confirmed, unconfirmed, locked in open offers). Atomic amounts are decimal strings.".into(), object(json!({}), &[]), &read_only),
        tool("get_history", "History", "Recent wallet transactions with per-asset balance changes (explorer data, display only).".into(),
            object(json!({ "limit": { "type": "integer", "minimum": 1, "maximum": 500, "description": "Max rows (default 50)." } }), &[]), &read_only),
        tool("get_markets", "DEX markets", "Markets listed by the configured DEX (untrusted data).".into(), object(json!({}), &[]), &read_only),
        tool("get_order_book", "Order book", "Bids and asks of a DEX market (untrusted data).".into(),
            object(json!({ "base": s(ASSET), "quote": s(ASSET) }), &["base", "quote"]), &read_only),
        tool("get_quote", "Quote", "Quote a swap via the DEX. Every offer is re-verified locally (signature, prevout) and totals recomputed.".into(),
            object(json!({ "sell": s(ASSET), "buy": s(ASSET), "amount": s(AMOUNT), "side": side }), &["sell", "buy", "amount"]), &read_only),
        tool("list_offers", "My offers", "Swap offers made by this wallet with on-chain status (open/spent/cancelled).".into(), object(json!({}), &[]), &read_only),
        tool("get_policy", "Signing policy", "The signing policy (mode, limits, allowlists) and the rolling 24h spend.".into(), object(json!({}), &[]), &read_only),
        tool("swap", "Swap", format!("Quote, verify and take DEX offers selling `sell` for `buy`.{MUTATING_NOTE}"),
            object(json!({ "sell": s(ASSET), "buy": s(ASSET), "amount": s(AMOUNT), "side": side, "max_slippage_bps": { "type": "integer", "minimum": 0, "description": "Max price impact vs the best offer, in bps (default 100)." }, "fee_rate": fee_rate }), &["sell", "buy", "amount"]), &mutating),
        tool("make_offer", "Make offer", format!("Create a maker swap offer giving `give_amount` of `give_asset` for `want_amount` of `want_asset` (splits an exact output first if needed), optionally posting it to the DEX.{MUTATING_NOTE}"),
            object(json!({ "give_asset": s(ASSET), "give_amount": s(AMOUNT), "want_asset": s(ASSET), "want_amount": s(AMOUNT), "post": { "type": "boolean", "description": "POST the offer to the DEX (default true)." }, "fee_rate": fee_rate }), &["give_asset", "give_amount", "want_asset", "want_amount"]), &mutating),
        tool("cancel_offer", "Cancel offer", format!("Cancel an offer by spending its output back to this wallet.{MUTATING_NOTE}"),
            object(json!({ "outpoint": s("Offered output as <txid>:<vout>."), "fee_rate": fee_rate }), &["outpoint"]), &mutating),
        tool("send", "Send", format!("Send an asset to an explicit (unconfidential) address.{MUTATING_NOTE}"),
            object(json!({ "asset": s(ASSET), "amount": s(AMOUNT), "recipient": s("Recipient address."), "fee_rate": fee_rate }), &["asset", "amount", "recipient"]), &mutating),
        tool("issue_asset", "Issue asset", format!("Issue a new explicit asset (optionally with reissuance tokens) and optionally register it with the asset registry.{MUTATING_NOTE}"),
            object(json!({
                "name": s("Asset name (1-255 chars)."),
                "ticker": s("Ticker, 3-24 chars of [A-Za-z0-9.-]."),
                "precision": { "type": "integer", "minimum": 0, "maximum": 8 },
                "amount": s("Amount to issue, decimal in the new asset's precision or atomic:<n>."),
                "token_amount": s("Reissuance tokens (whole units, default 0)."),
                "register": { "type": "boolean", "description": "Register with the asset registry after broadcast (default true)." },
                "fee_rate": fee_rate,
            }), &["name", "ticker", "precision", "amount"]), &mutating),
    ]
}

fn arg_str<'a>(args: &'a Value, key: &str) -> Result<&'a str> {
    args.get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("missing or non-string argument `{key}`"))
}

fn arg_u64(args: &Value, key: &str) -> Result<Option<u64>> {
    match args.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(v) => v
            .as_u64()
            .map(Some)
            .ok_or_else(|| anyhow!("argument `{key}` must be a non-negative integer")),
    }
}

fn arg_bool(args: &Value, key: &str, default: bool) -> Result<bool> {
    match args.get(key) {
        None | Some(Value::Null) => Ok(default),
        Some(v) => v
            .as_bool()
            .ok_or_else(|| anyhow!("argument `{key}` must be a boolean")),
    }
}

fn exact_out(args: &Value) -> Result<bool> {
    match args.get("side").and_then(Value::as_str) {
        None | Some("exact_in") => Ok(false),
        Some("exact_out") => Ok(true),
        Some(other) => bail!("side must be exact_in or exact_out, not {other:?}"),
    }
}

impl Backend for Wallet {
    fn call_tool(&self, name: &str, a: &Value) -> Result<Value> {
        if !a.is_object() {
            bail!("arguments must be an object");
        }
        let exec = Exec::Sign;
        match name {
            "get_address" => self.address(),
            "get_balances" => self.balances(),
            "get_history" => self.history(arg_u64(a, "limit")?.unwrap_or(50).min(500) as usize),
            "get_markets" => self.markets(),
            "get_order_book" => self.order_book(arg_str(a, "base")?, arg_str(a, "quote")?),
            "get_quote" => self.quote(
                arg_str(a, "sell")?,
                arg_str(a, "buy")?,
                arg_str(a, "amount")?,
                exact_out(a)?,
            ),
            "list_offers" => self.offer_list(),
            "get_policy" => self.policy_status(),
            "swap" => self.swap(
                arg_str(a, "sell")?,
                arg_str(a, "buy")?,
                arg_str(a, "amount")?,
                exact_out(a)?,
                arg_u64(a, "max_slippage_bps")?,
                arg_u64(a, "fee_rate")?,
                exec,
            ),
            "make_offer" => self.offer_make(
                arg_str(a, "give_asset")?,
                arg_str(a, "give_amount")?,
                arg_str(a, "want_asset")?,
                arg_str(a, "want_amount")?,
                arg_bool(a, "post", true)?,
                arg_u64(a, "fee_rate")?,
                exec,
            ),
            "cancel_offer" => {
                self.offer_cancel(arg_str(a, "outpoint")?, arg_u64(a, "fee_rate")?, exec)
            }
            "send" => self.send(
                arg_str(a, "asset")?,
                arg_str(a, "amount")?,
                arg_str(a, "recipient")?,
                arg_u64(a, "fee_rate")?,
                exec,
            ),
            "issue_asset" => {
                let precision = arg_u64(a, "precision")?
                    .ok_or_else(|| anyhow!("missing argument `precision`"))?;
                let precision =
                    u8::try_from(precision).map_err(|_| anyhow!("precision must be 0-8"))?;
                self.issue(
                    arg_str(a, "name")?,
                    arg_str(a, "ticker")?,
                    precision,
                    arg_str(a, "amount")?,
                    a.get("token_amount").and_then(Value::as_str).unwrap_or("0"),
                    arg_bool(a, "register", true)?,
                    arg_u64(a, "fee_rate")?,
                    exec,
                )
            }
            other => bail!("unknown tool {other:?}"),
        }
    }
}

pub struct Server<B: Backend> {
    backend: B,
    tool_names: Vec<String>,
}

fn rpc_error(id: Value, code: i64, message: &str) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message } })
}

fn rpc_result(id: Value, result: Value) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "result": result })
}

impl<B: Backend> Server<B> {
    pub fn new(backend: B) -> Self {
        let tool_names = tools()
            .iter()
            .filter_map(|t| t["name"].as_str().map(str::to_owned))
            .collect();
        Self {
            backend,
            tool_names,
        }
    }

    /// Handle one line; `None` for notifications (no response).
    pub fn handle_line(&self, line: &str) -> Option<Value> {
        let message: Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(_) => return Some(rpc_error(Value::Null, -32700, "parse error")),
        };
        let Some(object) = message.as_object() else {
            return Some(rpc_error(
                Value::Null,
                -32600,
                "invalid request (batches are not supported)",
            ));
        };
        let id = object.get("id").cloned();
        let method = object.get("method").and_then(Value::as_str);
        if object.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
            return id.map(|id| rpc_error(id, -32600, "invalid request: jsonrpc must be \"2.0\""));
        }
        let Some(method) = method else {
            // A response from the client (we never send requests): ignore.
            return None;
        };
        let Some(id) = id else {
            // Notifications (`notifications/initialized`, cancellations, …).
            return None;
        };
        if !(id.is_string() || id.is_i64() || id.is_u64()) {
            return Some(rpc_error(Value::Null, -32600, "invalid request id"));
        }
        let params = object.get("params").cloned().unwrap_or(json!({}));
        Some(match method {
            "initialize" => rpc_result(
                id,
                json!({
                    "protocolVersion": PROTOCOL_VERSION,
                    "capabilities": { "tools": { "listChanged": false } },
                    "serverInfo": { "name": "epw", "title": "Elements+ headless wallet", "version": env!("CARGO_PKG_VERSION") },
                    "instructions": "ECX Alpha (Elements+) wallet. Amounts are strings: decimals in asset precision or atomic:<n>. Mutating tools are gated by the user's policy.toml; when a result has status approval_required, show the review and approve_command to the human and stop — never try to approve it yourself.",
                }),
            ),
            "ping" => rpc_result(id, json!({})),
            "tools/list" => rpc_result(id, json!({ "tools": tools() })),
            "tools/call" => {
                let Some(name) = params.get("name").and_then(Value::as_str) else {
                    return Some(rpc_error(id, -32602, "tools/call requires a string `name`"));
                };
                if !self.tool_names.iter().any(|t| t == name) {
                    return Some(rpc_error(id, -32602, &format!("unknown tool: {name}")));
                }
                let args = params.get("arguments").cloned().unwrap_or(json!({}));
                let (structured, is_error) = match self.backend.call_tool(name, &args) {
                    Ok(value) => (value, false),
                    Err(error) => (error_json(&error), true),
                };
                let structured = if structured.is_object() {
                    structured
                } else {
                    json!({ "value": structured })
                };
                rpc_result(
                    id,
                    json!({
                        "content": [{ "type": "text", "text": serde_json::to_string_pretty(&structured).unwrap_or_default() }],
                        "structuredContent": structured,
                        "isError": is_error,
                    }),
                )
            }
            _ => rpc_error(id, -32601, &format!("method not found: {method}")),
        })
    }

    /// Serve until stdin closes.
    pub fn serve(&self, input: impl BufRead, mut output: impl Write) -> Result<()> {
        for line in input.lines() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            if let Some(response) = self.handle_line(&line) {
                let mut text = serde_json::to_string(&response)?;
                text.push('\n');
                output.write_all(text.as_bytes())?;
                output.flush()?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    #[derive(Default)]
    struct Fake {
        calls: RefCell<Vec<(String, Value)>>,
    }

    impl Backend for &Fake {
        fn call_tool(&self, name: &str, args: &Value) -> Result<Value> {
            self.calls.borrow_mut().push((name.into(), args.clone()));
            match name {
                "get_balances" => Ok(json!({ "balances": [{ "asset_id": "aa", "amount": "5" }] })),
                "send" => Err(anyhow!(crate::wallet::StructuredError(json!({
                    "status": "refused", "message": "refused by policy: limit", "decision": { "allowed": false }
                })))),
                "swap" => Ok(json!({ "status": "approval_required", "approval_hash": "ab" })),
                _ => Err(anyhow!("boom")),
            }
        }
    }

    fn call(server: &Server<&Fake>, request: Value) -> Option<Value> {
        server.handle_line(&request.to_string())
    }

    #[test]
    fn initialize_ping_and_list() {
        let fake = Fake::default();
        let server = Server::new(&fake);
        let init = call(&server, json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"0"}}})).unwrap();
        assert_eq!(init["id"], 1);
        assert_eq!(init["result"]["protocolVersion"], PROTOCOL_VERSION);
        assert!(init["result"]["capabilities"]["tools"].is_object());
        assert!(call(
            &server,
            json!({"jsonrpc":"2.0","method":"notifications/initialized"})
        )
        .is_none());
        assert_eq!(
            call(&server, json!({"jsonrpc":"2.0","id":"p","method":"ping"})).unwrap()["result"],
            json!({})
        );
        let list = call(
            &server,
            json!({"jsonrpc":"2.0","id":2,"method":"tools/list"}),
        )
        .unwrap();
        let tools = list["result"]["tools"].as_array().unwrap();
        let names: Vec<&str> = tools.iter().map(|t| t["name"].as_str().unwrap()).collect();
        for required in [
            "get_balances",
            "get_address",
            "get_markets",
            "get_order_book",
            "get_quote",
            "swap",
            "make_offer",
            "cancel_offer",
            "send",
            "issue_asset",
            "get_history",
        ] {
            assert!(names.contains(&required), "missing {required}");
        }
        for tool in tools {
            assert_eq!(tool["inputSchema"]["type"], "object");
            let text = tool.to_string().to_lowercase();
            assert!(
                !text.contains("mnemonic") && !text.contains("keystore"),
                "{text}"
            );
        }
    }

    #[test]
    fn tool_calls_success_and_errors() {
        let fake = Fake::default();
        let server = Server::new(&fake);
        let ok = call(&server, json!({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"get_balances","arguments":{}}})).unwrap();
        assert_eq!(ok["result"]["isError"], false);
        assert_eq!(
            ok["result"]["structuredContent"]["balances"][0]["amount"],
            "5"
        );
        assert_eq!(ok["result"]["content"][0]["type"], "text");

        let refused = call(&server, json!({"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"send","arguments":{"asset":"ECX","amount":"1","recipient":"x"}}})).unwrap();
        assert_eq!(refused["result"]["isError"], true);
        assert_eq!(refused["result"]["structuredContent"]["status"], "refused");
        assert_eq!(
            refused["result"]["structuredContent"]["decision"]["allowed"],
            false
        );

        let pending = call(&server, json!({"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"swap","arguments":{}}})).unwrap();
        assert_eq!(pending["result"]["isError"], false);
        assert_eq!(
            pending["result"]["structuredContent"]["status"],
            "approval_required"
        );

        let failing = call(
            &server,
            json!({"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"get_markets"}}),
        )
        .unwrap();
        assert_eq!(failing["result"]["isError"], true);
        assert_eq!(failing["result"]["structuredContent"]["message"], "boom");
        // Missing `arguments` defaults to {}.
        assert_eq!(fake.calls.borrow().last().unwrap().1, json!({}));
    }

    #[test]
    fn protocol_errors() {
        let fake = Fake::default();
        let server = Server::new(&fake);
        assert_eq!(
            server.handle_line("{nope").unwrap()["error"]["code"],
            -32700
        );
        assert_eq!(server.handle_line("[]").unwrap()["error"]["code"], -32600);
        assert_eq!(
            call(&server, json!({"jsonrpc":"1.0","id":1,"method":"ping"})).unwrap()["error"]
                ["code"],
            -32600
        );
        assert_eq!(
            call(
                &server,
                json!({"jsonrpc":"2.0","id":1,"method":"resources/list"})
            )
            .unwrap()["error"]["code"],
            -32601
        );
        let unknown = call(&server, json!({"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"export_mnemonic"}})).unwrap();
        assert_eq!(unknown["error"]["code"], -32602);
        assert!(
            fake.calls.borrow().is_empty(),
            "unknown tools never reach the backend"
        );
        assert_eq!(
            call(
                &server,
                json!({"jsonrpc":"2.0","id":8,"method":"tools/call","params":{}})
            )
            .unwrap()["error"]["code"],
            -32602
        );
        assert_eq!(
            call(
                &server,
                json!({"jsonrpc":"2.0","id":{"x":1},"method":"ping"})
            )
            .unwrap()["error"]["code"],
            -32600
        );
    }

    #[test]
    fn serve_is_newline_delimited() {
        let fake = Fake::default();
        let server = Server::new(&fake);
        let input = b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}\n\n{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"ping\"}\n";
        let mut out = Vec::new();
        server.serve(&input[..], &mut out).unwrap();
        let text = String::from_utf8(out).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 2);
        assert_eq!(serde_json::from_str::<Value>(lines[1]).unwrap()["id"], 2);
    }
}
