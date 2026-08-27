import { Gamepad2, Microscope } from "lucide-react";
import { NavLink } from "react-router-dom";

export function LabModeSwitch() {
  return (
    <nav className="lab-mode-switch" aria-label="实验舱视图">
      <NavLink to="/lab">
        <Microscope size={16} aria-hidden="true" />
        专业调查
      </NavLink>
      <NavLink to="/challenge">
        <Gamepad2 size={16} aria-hidden="true" />
        侦探挑战
      </NavLink>
    </nav>
  );
}
