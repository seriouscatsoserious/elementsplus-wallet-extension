import type { Screen, ScreenName } from "../lib/app.js";
import { h } from "../lib/dom.js";
import { confirmPhraseScreen, importScreen, lockScreen, passwordScreen, showPhraseScreen, welcomeScreen } from "./access.js";
import { activityScreen } from "./activity.js";
import { confirmScreen, sendScreen, sentScreen } from "./send.js";
import { advancedScreen, networkSettingsScreen, phraseScreen, settingsScreen, sitesScreen } from "./settings.js";
import { homeScreen, manageScreen, receiveScreen } from "./wallet.js";

const loading: Screen = () => h("div", { class: "screen pad center-all" }, h("span", { class: "spin lg", "aria-label": "Loading" }));

export const SCREENS: Record<ScreenName, Screen> = {
  loading,
  lock: lockScreen,
  welcome: welcomeScreen,
  "show-phrase": showPhraseScreen,
  "confirm-phrase": confirmPhraseScreen,
  import: importScreen,
  password: passwordScreen,
  home: homeScreen,
  manage: manageScreen,
  activity: activityScreen,
  send: sendScreen,
  confirm: confirmScreen,
  sent: sentScreen,
  receive: receiveScreen,
  settings: settingsScreen,
  "settings-network": networkSettingsScreen,
  "settings-sites": sitesScreen,
  "settings-phrase": phraseScreen,
  "settings-advanced": advancedScreen,
};
