import React from 'react';
import './Popup.css';  // Include necessary CSS for styling

const AIPopup = ({ aiResponse, onClose }) => {
  return (
    <div className="popup-overlay">
      <div className="popup-content">
        
        <h2>AI Analysis</h2>
        <div className='close_button'>
        <button className="closeButton" onClick={onClose}>X</button>
        </div>
        <div className="popup-field">
          <strong>Email Status:</strong>
          <p className='clr-background'>{aiResponse.email}</p>
        </div>
        <div className="popup-field">
          <strong>Reason:</strong>
          <p className='clr-background'>{aiResponse.reason}</p>
        </div>
        <div className="popup-field">
          <strong>Suggestion:</strong>
          <p className='clr-background'>{aiResponse.suggestion}</p>
          <p style={{fontSize:"11px", backgroundColor:"#ad5a9573", padding:"10px", borderRadius:"5px", textAlign:"center"}}>Note: This is AI-generated text. Please note that it may not be entirely accurate or reliable. Always consider other factors as well.</p>

        </div>
        
      </div>
    </div>
  );
};

export default AIPopup;
