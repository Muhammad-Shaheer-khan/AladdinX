import React, { useState } from 'react';

const SPFStatus = ({ spf }) => {
  const [spfDropdownOpen, setSpfDropdownOpen] = useState(false);

  const toggleSpfDropdown = () => {
    setSpfDropdownOpen(!spfDropdownOpen);
  };

  return (
    <div className='spf-section'>
      {/* Main SPF Status Table */}
      <table className="spf-status-table" onClick={toggleSpfDropdown}>
        <thead>
          <tr>
            <th>SPF Status</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td>
              SPF Status: {spf.SPF_Status} {spf['SPF Status'] === 'Pass' ? ' Pass ✔️' : spf['SPF Status'] === 'Fail' ? 'Fail ❌' : 'SoftFail ⚠️'}
            </td>
          </tr>
        </tbody>
      </table>

      {/* Dropdown Details Table */}
      {spfDropdownOpen && (
        <table className="spf-details-table">
        <thead>
          <tr>
            <th>Bounce Section</th>
            <th>Sign Analysis</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td>{spf['Bounce Section']}</td>
            <td rowSpan={spf['Sign Analysis'].length}>
              <ul>
                {spf['Sign Analysis'].map((item, index) => (
                  <li key={index}>{item}</li>
                ))}
              </ul>
            </td>
          </tr>
        </tbody>
      </table>
      
      )}
    </div>
  );
};

export default SPFStatus;
