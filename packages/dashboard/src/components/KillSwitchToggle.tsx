import { useState } from "react";
import { useDashboard } from "../hooks/useDashboardStore.js";

export function KillSwitchToggle() {
  const { state, sendMessage } = useDashboard();
  const [confirming, setConfirming] = useState(false);

  const handleClick = () => {
    if (state.killSwitchActive) {
      // Deactivate immediately
      sendMessage({ type: "toggleKillSwitch" });
    } else {
      // Require confirmation to activate
      setConfirming(true);
    }
  };

  const handleConfirm = () => {
    sendMessage({ type: "toggleKillSwitch" });
    setConfirming(false);
  };

  return (
    <div className="kill-switch-container">
      {confirming ? (
        <div className="kill-confirm">
          <span>Deny ALL calls?</span>
          <button className="kill-btn-confirm" onClick={handleConfirm}>
            Yes
          </button>
          <button onClick={() => setConfirming(false)}>Cancel</button>
        </div>
      ) : (
        <button
          className={`kill-btn ${state.killSwitchActive ? "kill-active" : ""}`}
          onClick={handleClick}
          title={
            state.killSwitchActive
              ? "Kill switch ON — click to deactivate"
              : "Activate kill switch — denies ALL tool calls"
          }
        >
          {state.killSwitchActive ? "KILL ACTIVE" : "KILL SWITCH"}
        </button>
      )}
    </div>
  );
}
