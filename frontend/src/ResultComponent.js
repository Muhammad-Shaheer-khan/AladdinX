// Refactored ResultBox.js
import React, { useState, useEffect } from 'react';
import './ResultComponent.css'; // Assuming you have this CSS file for styling

const ResultBox = ({ emailMatchData, spfData, dkimData, spamData, mxData, dmarcData, SuspiciousWords }) => {
  const [selectedDetails, setSelectedDetails] = useState(null);

  // Reset selectedDetails when new data comes in
  useEffect(() => {
    if (emailMatchData && spfData && dkimData && spamData && mxData && dmarcData && SuspiciousWords) {
      setSelectedDetails(null);
    }
  }, [emailMatchData, spfData, dkimData, spamData, mxData, dmarcData, SuspiciousWords]);
  

  const handleEmailClick = () => {
    setSelectedDetails({
      title: 'Path Match  ',  // Add this title field
      type: 'email',
      details: {
        'Sender Domain': emailMatchData.sendDomain,
        'Return Path Domain': emailMatchData.returnDomain,
      }
    });
  };

  const handleSpfClick = () => {
    setSelectedDetails({
      title: 'SPF  ',  // Add this title field
      type: 'spf',
      details: {
        'Bounce Section': spfData.bounceSection,
        'Sign Analysis': spfData.signAnalysis
      }
    });
  };

  const handleDkimClick = () => {
    setSelectedDetails({
      title: 'DKIM  ',  // Add this title field
      type: 'dkim',
      details: dkimData.details
    });
  };

  // New click handler for spam data
  const handleSpamClick = () => {
    setSelectedDetails({
      title: 'SPAM Details  ',  // Add this title field
      type: 'spam',
      details: {
        'X-Spam-Flag': spamData['X-Spam-Flag'],
        'X-Spam-Flag Interpretation': spamData['X-Spam-Flag Interpretation'],
        'X-Spam-Score': spamData['X-Spam-Score'],
        'X-Spam-Score Interpretation': spamData['X-Spam-Score Interpretation'],
      },
    });
  };
  

  const handleMxClick = () => {
    setSelectedDetails({
      title: 'Mail Exchange  ',  // Add this title field
      type: 'mx',
      details: {
        'From Domains': mxData?.from_domains?.[0] || 'N/A',
        'From Domains Interpretation': mxData?.from_domains?.[1] || 'N/A',
        'MX Routes': mxData?.mx_routes?.[0]?.join(', ') || 'N/A',
        'MX Routes Interpretation': mxData?.mx_routes?.[1] || 'N/A',
      },
    });
  };


  const handleDmarcClick = () => {
    setSelectedDetails({
      title:'DMARC  ',
      type: 'dmarc',
      details: dmarcData || {}
    });
  };
  
  const handleSuspiciousWordsClick = () => {
    setSelectedDetails({
      title: 'Suspicious Words',
      type: 'suspiciousWords',
      details: SuspiciousWords || {},
    });
  };

  

  const renderDetailsTable = (details) => {
    return (
      <table className="email-details-table">
        <tbody>
          {Object.entries(details).map(([key, value], index) => (
            <tr key={index}>
              <th>{key}</th>
              <td>
                {Array.isArray(value) 
                  ? value.map((item, index) => (
                      Array.isArray(item) 
                        ? item.map((subItem, subIndex) => (
                            <span key={subIndex}>
                              {subItem}
                              {subIndex < item.length - 1 ? ', ' : ''}
                              <br />  {/* Adding a break after each item in the tuple */}
                            </span>
                          ))
                        : <span key={index}>{item}<br /></span>
                    ))
                  : value}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    );
  };
  
  return (
    <div className="email-match-container">
      {/* Left section - Always displays email match, SPF status, and DKIM status */}
      <div className="email-match-left">
        <table className="email-match-table">
          <tbody>
            <tr onClick={handleEmailClick} className="clickable-row">
              <td>
                {emailMatchData.emailMatch
                  ? '✔️ Sender & Return-path match'
                  : '❌ Sender & Return-path mismatch'}
              </td>
            </tr>
            <tr onClick={handleSpfClick} className="clickable-row">
              <td>
                {spfData.spfStatus === 'Pass'
                  ? '✔️ SPF Passed'
                  : '❌ SPF Failed'}
              </td>
            </tr>
            <tr onClick={handleDkimClick} className="clickable-row">
              <td>
                {dkimData.status === 'pass'
                  ? '✔️ DKIM Passed'
                  : dkimData.status === 'fail'
                  ? '❌ DKIM Failed'
                  : '❓ DKIM Undefined'}
              </td>
            </tr>
            <tr onClick={handleSpamClick} className="clickable-row">
              <td>
                {spamData.spam_detail === 'found'
                  ? '🟡 Spam Detail Found '
                  : '❕ No Spam Detail Found'}
              </td>
            </tr>
            <tr onClick={handleMxClick} className="clickable-row">
              <td>
                {mxData['Mail Exchange Detail'] === 'found'
                  ? '✔️ Mail Exchange Detail Found'
                  : '❌ Mail Exchange Detail Not Found'}
              </td>
            </tr>
            <tr onClick={handleDmarcClick} className="clickable-row">
              <td>
                {dmarcData['DMARC Result'] === 'pass'
                  ? `✔️ DMARC Result Passed` 
                  : dmarcData['DMARC Result']  === 'fail'
                  ? '❌ DMARC Status Failed'
                  : '❓ DMARC Status Undefined'}
              </td>
            </tr>
            <tr onClick={handleSuspiciousWordsClick} className="clickable-row">
              <td>
                {SuspiciousWords['Suspicious words percentage'] === '0%'
                  ? `✔️ Email Body clear` 
                  : SuspiciousWords['Suspicious words percentage']  === '100%'
                  ? '⛔ Max Suspicious Words found'
                  : '⚠️ Suspicious Words found'}
              </td>
            </tr>


          </tbody>
        </table>
      </div>

      {/* Right section - Displays details if clicked, otherwise shows message */}
      <div className="email-match-right" style={{display:'revert'}}>
        {selectedDetails ? (
          <>
            {/* <div style={{ display: 'relative', justifyContent: 'center', marginBottom: '10px' }}>   */}
              <h3>{selectedDetails.title}</h3>
            {/* </div> */}
            {/* Display the title */}
            {renderDetailsTable(selectedDetails.details)}
          </>
        ) : (
          <p style={{marginTop: '150px'}}>Click any row to view details</p>
        )}
      </div>

    </div>
  );
};

export default ResultBox;
