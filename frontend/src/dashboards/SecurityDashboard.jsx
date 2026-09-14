import { NavLink, Outlet, useNavigate } from "react-router-dom";
import "./SecurityDashboard.css";

function SecurityDashboard() {
  const navigate = useNavigate();

  const handleLogout = () => {
    const confirmLogout = window.confirm(
      "Are you sure you want to logout?"
    );

    if (confirmLogout) {
      navigate("/");
    }
  };

  return (
    <div className="security-container">

      {/* ===========================
          SIDEBAR
      =========================== */}

      <aside className="security-sidebar">

        <div className="logo">
          <div className="logo-icon">NS</div>
          <div>
            <h2>NetShield AI</h2>
            <p>Security Analyst Panel</p>
          </div>
        </div>

        <nav>

          {/* Dashboard */}
          <NavLink
            to="/security/dashboard"
            className={({ isActive }) =>
              isActive ? "active-link" : ""
            }
          >
            <span className="nav-icon">DB</span>
            <span>Dashboard</span>
          </NavLink>

          {/* Live Network */}
          <NavLink
            to="/security/network"
            className={({ isActive }) =>
              isActive ? "active-link" : ""
            }
          >
            <span className="nav-icon">NW</span>
            <span>Live Network</span>
          </NavLink>

          {/* Threat Analysis */}
          <NavLink
            to="/security/threats"
            className={({ isActive }) =>
              isActive ? "active-link" : ""
            }
          >
            <span className="nav-icon">TA</span>
            <span>Threat Analysis</span>
          </NavLink>

          {/* Incident Investigation */}
          <NavLink
            to="/security/incidents"
            className={({ isActive }) =>
              isActive ? "active-link" : ""
            }
          >
            <span className="nav-icon">IN</span>
            <span>Incident Investigation</span>
          </NavLink>

          {/* AI Predictions */}
          <NavLink
            to="/security/ai"
            className={({ isActive }) =>
              isActive ? "active-link" : ""
            }
          >
            <span className="nav-icon">AI</span>
            <span>AI Predictions</span>
          </NavLink>

          {/* Threat Timeline */}
          <NavLink
            to="/security/timeline"
            className={({ isActive }) =>
              isActive ? "active-link" : ""
            }
          >
            <span className="nav-icon">TL</span>
            <span>Threat Timeline</span>
          </NavLink>

          {/* Reports */}
          <NavLink
            to="/security/reports"
            className={({ isActive }) =>
              isActive ? "active-link" : ""
            }
          >
            <span className="nav-icon">RP</span>
            <span>Reports</span>
          </NavLink>

          {/* PCAP Analytics */}
          <NavLink
            to="/security/pcap"
            className={({ isActive }) =>
              isActive ? "active-link" : ""
            }
          >
            <span className="nav-icon">PC</span>
            <span>PCAP Analytics</span>
          </NavLink>

        </nav>

        {/* ===========================
            LOGOUT
        =========================== */}

        <div className="sidebar-footer">
          <button
            className="logout-btn"
            onClick={handleLogout}
          >
            <span className="nav-icon">LO</span>
            <span>Logout</span>
          </button>
        </div>

      </aside>

      {/* ===========================
          MAIN CONTENT
      =========================== */}

      <main className="security-main">
        <Outlet />
      </main>

    </div>
  );
}

export default SecurityDashboard;