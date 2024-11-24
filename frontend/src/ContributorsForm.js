// ContributorsForm.js
import React from 'react';
import './ContributorsForm.css'; // For styling

const ContributorsForm = ({ onClose }) => {
 
  return (
    <div className="contributor-popup-container">
      <div className="contributor-popup-content">
        <h2>Contribute to Our Project</h2>
        <p>
          To feature your logo in our project and collaborate with us, please send an email to 
          <strong> shaheerk2233@gmail.com </strong> with the following details:
        </p>
        <ul className="details-list">
          <li><strong>Company Name:</strong> [Your Company Name]</li>
          <li><strong>Email:</strong> [Your Contact Email]</li>
          <li><strong>Logo URL:</strong> [Link to Your Logo]</li>
          <li><strong>Description:</strong> [Brief Description of Your Contribution]</li>
        </ul>
        <button className="cancel-button" onClick={onClose}>Cancel</button>
      </div>
    </div>
  );
  
};

export default ContributorsForm;
