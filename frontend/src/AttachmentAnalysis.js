// AttachmentAnalysis.js
import React from 'react';

const AttachmentAnalysis = ({ attachmentsResult }) => {
  if (!attachmentsResult || Object.keys(attachmentsResult).length === 0) {
    return <div>No attachments</div>;
  }

  const suspiciousFiles = attachmentsResult.suspicious_files;
  const suspiciousLinks = attachmentsResult.suspicious_links;

  return (
    <div>
      <h2>Attachment Analysis</h2>
      {suspiciousFiles.length > 0 && (
        <table>
          <thead>
            <tr>
              <th>File Name</th>
              <th>Category</th>
            </tr>
          </thead>
          <tbody>
            {suspiciousFiles.map((file, index) => (
              <tr key={index}>
                <td>{file.name}</td>
                <td>{file.category}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {suspiciousLinks.length > 0 && (
        <table>
          <thead>
            <tr>
              <th>Link</th>
            </tr>
          </thead>
          <tbody>
            {suspiciousLinks.map((link, index) => (
              <tr key={index}>
                <td>{link}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
};

export default AttachmentAnalysis;