import React, { useState } from 'react';
import './Navbar.css';
import logo from './assets/images/logo.png'; 
import BuyMeACoffee from './assets/images/BuyMeACoffee.png';
import DemoVideo from './DemoVideo';

function Navbar({ onContributeClick }) {
  const [isPopupVisible, setIsPopupVisible] = useState(false);
  const [isDemoVisible, setIsDemoVisible] = useState(false);

  const handleDemoOpen = () => {
    setIsDemoVisible(true);
  };

  const handleDemoClose = () => {
    setIsDemoVisible(false);
  };
  const handleButtonClick = () => {
    setIsPopupVisible(true);
  };

  const handlePopupClose = () => {
    setIsPopupVisible(false);
  };

  return (
    <nav className="navbar">
      <div className="navbar-logo">
        <img src={logo} alt="Logo" className="navbar-logo-img" />
        <span className="logo-text">AʅαԃԃιɳX.</span>
      </div>
      
      <div className="navbar-links">
        <a href="#buymeacoffee" style={{ padding: '1px' }} onClick={handleButtonClick}>
          <img src={BuyMeACoffee} alt="BuyMeACoffee" style={{ height: '40px', marginRight: '5px' }} />
        </a>

        <div className={`app-container ${isDemoVisible ? 'blur-background' : ''}`}>
          {/* <h1>Welcome to the Demo</h1> */}
          <a href="#demo" onClick={handleDemoOpen}>Demo Guide</a>

          {isDemoVisible && <DemoVideo onClose={handleDemoClose} />}
        </div>

        {/* Modified Contribute Link */}
        <a href="#contribute" onClick={(e) => {
          e.preventDefault();
          onContributeClick(); // Trigger the contribute form when clicked
        }}>Contribute</a>

        <div className="dropdown">
          <div className="dropbtn">Connect me!</div>
          <div className="dropdown-content">
            <a href="https://linkedin.com/in/m-shaheer-khan" target="_blank" rel="noopener noreferrer">LinkedIn</a>
            <a href="https://github.com/Muhammad-Shaheer-khan/" target="_blank" rel="noopener noreferrer">GitHub</a>
            <a href="https://medium.com/@shaheerk2233" target="_blank" rel="noopener noreferrer">Medium</a>
          </div>
        </div>
      </div>

      {/* Popup */}
      {isPopupVisible && (
        <div className="popup-container" style={{ marginTop: "-80px" }}>
        
          <div className="popup-content">
            <p style={{ textAlign: "center", backgroundColor:"#ad5a9573", padding:"8px", borderRadius:"10px" }}>
            Feeling generous? Buy me a coffee to fuel my work.
            </p>
            <div style={{ marginTop: "20px" }}>
              <div>
              <h4>Nayapay Account</h4>
                <button
                  style={{
                    width: "30px",
                    height: "30px",
                    justifyContent: "center",
                    alignItems: "center",
                    padding: "0",
                    marginRight: "10px",
                    marginTop: "-3px"
                  }}
                >
                  💳
                </button>  
                  <span>Buy a Coffee via <strong>Nayapay</strong></span>
                  <span class="account-details"><strong>Account Name:</strong> M Shaheer khan</span>
                  <span class="account-details"><strong>Account Number:</strong> 4782 7800 2261 9160</span>
                
              </div>
            </div>
            
            <button onClick={handlePopupClose} style={{ marginTop: "20px" }}>
              Close
            </button>
          </div>
        </div>
      )}

    </nav>
  );
}

export default Navbar;
