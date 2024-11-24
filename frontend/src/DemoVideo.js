import React from 'react';
import './DemoVideo.css'; // Ensure this file is created and linked

const DemoVideo = ({ onClose }) => {
  return (
    <div className="demo-popup-container">
      <div className="demo-popup-content">
        <h2 style={{ textAlign: "center", marginBottom: "-20px" }}>
          Explore Email Analyzer: Your Guide
        </h2>
        <p>this demo.</p>
        <div className="video-container">
          <video width="780" height="420" controls>
            <source
              src={require('./assets/AladdinX.mp4')} // Correct relative path
              type="video/mp4"
            />
            Your browser does not support the video tag.
          </video>
        </div>
        <button className="cancel-button" onClick={onClose}>Cancel</button>
      </div>
    </div>
  );
};

export default DemoVideo;
