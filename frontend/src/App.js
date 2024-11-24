  import React, { useState, useEffect, useMemo } from 'react';
  import './App.css';
  import Navbar from './Navbar';
  import Loader from './loader'; 
  import lamp from './assets/images/lamp.png';
  import ProgressBar from './circle_progressBar';
  import ResultBox from './ResultComponent';
  import AIPopup from './AIPopup';  
  import ContributorsForm from './ContributorsForm';
function ScrollToBottom() {
  const element = document.getElementById("parsed-data-div");
  if (element) {
    element.scrollIntoView({ behavior: 'smooth' });
  }
}

function App() {
  const [emailHeader, setEmailHeader] = useState('');
  const [notification, setNotification] = useState(null);
  const [parsedData, setParsedData] = useState(null);
  const [isParsing, setIsParsing] = useState(false);
  const [searchTerm, setSearchTerm] = useState('');
  const [ipSearchTerm, setIpSearchTerm] = useState(''); 
  const [ipDetails, setIpDetails] = useState(null);
  const [graphData, setGraphData] = useState(null);
  const [attachmentsResult, setAttachmentsResult] = useState(null);
  const [emailMatchData, setEmailMatchData] = useState(null);
  const [spfData, setSpfData] = useState(null);
  const [dkimData, setDkimData] = useState(null);
  const [spamData, setspamData] = useState(null);
  const [mxData, setmxData] = useState(null);
  const [dmarcData, setdmarcData] = useState(null);
  const [SuspiciousWords, setSuspiciousWords] = useState(null);
  const [showPopup, setShowPopup] = useState(false); 
  const [aiResponse, setAiResponse] = useState(null); 
  const [showContributorsForm, setShowContributorsForm] = useState(false);

  const handleContributorsClick = () => {
    setShowContributorsForm(true);
  };

  const handleCloseForm = () => {
    setShowContributorsForm(false);
  };

  const handleTextareaChange = (event) => {
    setEmailHeader(event.target.value);
  };

  const handleSearchChange = (event) => {
    setSearchTerm(event.target.value.toLowerCase());
  };

  const handleIpSearchChange = (event) => {
    setIpSearchTerm(event.target.value.toLowerCase()); 
  };

  const handleSubmit = async () => {
    
      const fetchData = async () => {
        setIsParsing(true);
        const response = await fetch('/api/analyze-header/', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({ header: emailHeader }),
        });
  
        const data = await response.json();
  
        if (response.ok) {
          setNotification(null);
          setParsedData(data.result);
          setIpDetails(data.analysis);
          setGraphData(data.graph_details);
          setAttachmentsResult(data.attachments_result);
          setspamData(data.spamField);
          setmxData(data.mxRecord);
          setdmarcData(data.dmarcRecord);
          setSuspiciousWords(data.SuspiciousWords);
          setEmailMatchData({
            emailMatch: data.mail_match['email match'],
            sendDomain: data.mail_match['sendDomain'],
            returnDomain: data.mail_match['returnDomain'],
          });
          setSpfData({
            spfStatus: data.spf['SPF Status'],
            bounceSection: data.spf['Bounce Section'],
            signAnalysis: data.spf['Sign Analysis'],
          });
          setDkimData({
            status: Object.keys(data.dkim)[0], // Getting 'pass' or 'fail' from DKIM response
            details: data.dkim[Object.keys(data.dkim)[0]], // Getting details of the DKIM result
          });
          setAiResponse(data.aiRespose); 
        } else {
          setParsedData(null);
          setIpDetails(null);
          setNotification(data.error);
          setGraphData(null);
          setAttachmentsResult(null);
          setEmailMatchData(null); 
          setDkimData(null);
          setspamData(null);
          setdmarcData(null);
          setSuspiciousWords(null);
          setAiResponse(null);
        }
        setIsParsing(false);
      };
  
      fetchData();
  };

  const filteredData = parsedData
    ? Object.entries(parsedData).filter(([key, value]) =>
        key.toLowerCase().includes(searchTerm) ||
        value.toString().toLowerCase().includes(searchTerm)
      )
    : [];

  const filteredIpDetails = useMemo(() => {
    return ipDetails
      ? Object.entries(ipDetails).map(([source, details]) => {
          const filteredDetails = Object.entries(details).filter(([key, value]) =>
            key.toLowerCase().includes(ipSearchTerm) ||
            value.toString().toLowerCase().includes(ipSearchTerm)
          );
          return [source, Object.fromEntries(filteredDetails)];
        })
      : [];
  }, [ipDetails, ipSearchTerm]);


  // Adjust window2 based on ResultDiv
  useEffect(() => {
    const resultDivElement = document.querySelector('.ResultDiv');
    const window2Element = document.querySelector('.window2');

    if (resultDivElement && window2Element) {
      const resultDivHeight = resultDivElement.getBoundingClientRect().height;
      window2Element.style.top = `${resultDivElement.offsetTop + resultDivHeight + 30}px`;
    }
  }, [filteredIpDetails]);

  useEffect(() => {
    const window2Element = document.querySelector('.window2');
    const window3_Element = document.querySelector('.window3');

    if (window2Element && window3_Element) {
      const window2Height = window2Element.getBoundingClientRect().height;
      window3_Element.style.top = `${window2Element.offsetTop + window2Height + 40}px`;
    }
  });

  useEffect(() => {
    // Adjust parsed-data based on window3
    const window3Element = document.querySelector('.window3');
    const parsedDataElement = document.querySelector('.parsed-data');
  
    if (window3Element && parsedDataElement) {
      const window3Height = window3Element.getBoundingClientRect().height;
      parsedDataElement.style.top = `${window3Element.offsetTop + window3Height + 40}px`;
    }
  }, [filteredIpDetails]); // This useEffect runs whenever filteredIpDetails changes

  // Adjust window2 based on window3
  useEffect(() => {
    const window3Element = document.querySelector('.window3');
    const window2Element = document.querySelector('.window2');

    if (window3Element && window2Element) {
      const window3Height = window3Element.getBoundingClientRect().height;
      window2Element.style.top = `${window3Element.offsetTop + window3Height + 40}px`;
    }
  }, []);

  useEffect(() => {
    // Adjust the position of the spacer div based on parsed-data div
    const parsedDataElement = document.querySelector('.parsed-data');
    const spacerElement = document.querySelector('.spacer');
  
    if (parsedDataElement && spacerElement) {
      const parsedDataHeight = parsedDataElement.getBoundingClientRect().height;
      spacerElement.style.top = `${parsedDataElement.offsetTop + parsedDataHeight + 40}px`;
    }
  }, []);
  


  useEffect(() => {
    const fetchEmailMatchData = async () => {
      try {
        const response = await fetch('/api/email-match/');
        const data = await response.json();
        setEmailMatchData({
          emailMatch: data.mail_match['email match'],
          sendDomain: data.mail_match['sendDomain'],
          returnDomain: data.mail_match['returnDomain'],
        });
        setSpfData({
          spfStatus: data.spf['SPF Status'],
          bounceSection: data.spf['Bounce Section'],
          signAnalysis: data.spf['Sign Analysis'],
        });
        setDkimData({
          status: Object.keys(data.dkim)[0],
          details: data.dkim[Object.keys(data.dkim)[0]],
        }); // Capture DKIM data
      } catch (error) {
        console.error('Error fetching email match data:', error);
      }
    };

    fetchEmailMatchData();
  }, []);

  return (
    <div className="App">

      <Navbar onContributeClick={handleContributorsClick} />
      {showContributorsForm && <ContributorsForm onClose={handleCloseForm} />}

      <div className="window">
      <h1>Email Header Analyzer</h1>
        <textarea
          placeholder="Enter email header here..."
          value={emailHeader}
          onChange={handleTextareaChange}
        />
        <button onClick={handleSubmit} disabled={isParsing}>
          <img src={lamp} alt="Lamp" className="lamp-img" />
          Genie Boom {isParsing ? 'Parsing...' : ''}
        </button>
        {notification && <div className="notification">{notification}</div>}
      </div>

      {emailMatchData && Object.keys(emailMatchData).length > 0 && (
        <div className='ResultDiv'>
          <h2>Analysis Result</h2>
          <div className="App">
            <button className="ai-button" onClick={() => setShowPopup(true)}>
              View AI Analysis
            </button>
            {emailMatchData && spfData && dkimData && spamData && mxData && dmarcData && SuspiciousWords ? (
              <ResultBox
                emailMatchData={emailMatchData}
                spfData={spfData}
                dkimData={dkimData}
                spamData={spamData}
                mxData={mxData}
                dmarcData={dmarcData}
                SuspiciousWords={SuspiciousWords}
              />
            ) : (
              '--Refresh or boom again--'
            )}

            
          </div>
        </div>
      )}

      {showPopup && aiResponse && (
        <AIPopup aiResponse={aiResponse} onClose={() => setShowPopup(false)} />
      )}

      {/* IP Analysis */}
      {ipDetails && Object.keys(ipDetails).length > 0 && (
        <div className="window2">
          <h2>IP Analysis</h2>
          <div className="progress-bar-container" style={{ position:"fixed", left:"340px", top:'120px'}}>    
                {console.log("Malicious reports:", graphData.malicious)}
                <ProgressBar percentage={graphData.malicious} sum={graphData.sum}/>
            </div>

            <table style={{ width: '50%', position:'fixed', left:'700px', top:'150px'}}>
        
        {graphData && (
          <>
            <tr>
              <td style={{ width: '20%' }}>Harmless</td>
              <td style={{ width: '30%' }}>{graphData.harmless}</td>
            </tr>
            <tr>
              <td style={{ width: '20%' }}>Undetected</td>
              <td style={{ width: '30%' }}>{graphData.undetected}</td>
            </tr>
            <tr>
              <td style={{ width: '20%' }}>Suspicious</td>
              <td style={{ width: '30%' }}>{graphData.suspicious}</td>
            </tr>
            <tr>
              <td style={{ width: '20%' }}>Malicious</td>
              <td style={{ width: '30%' }}>{graphData.malicious}</td>
            </tr>
          </>
        )}

      </table>
      <div className="search-filter">

          <input
            type="text"
            placeholder="Search IP details..."
            value={ipSearchTerm} 
            onChange={handleIpSearchChange}
          />
        </div>
          <table style={{marginTop:"300px"}}>

          <tbody>
        {filteredIpDetails.map(([source, details], index) => {
          const entries = Object.entries(details);
          return entries.map(([key, value], subIndex) => {
            const nextEntry = entries[subIndex + 1];
            return (
              subIndex % 2 === 0 && (
                <tr key={`${index}-${subIndex}`}>
                  <td className="key">{key}</td>
                  <td className="value">
                    {key === "flag" ? (
                      <img src={value} alt="Country Flag" style={{ width: "64px", height: "auto" }} />
                    ) : (
                      value
                    )}
                  </td>
                  {nextEntry ? (
                    <>
                      <td className="key">{nextEntry[0]}</td>
                      <td className="value">
                        {nextEntry[0] === "flag" ? (
                          <img src={nextEntry[1]} alt="Country Flag" style={{ width: "64px", height: "auto" }} />
                        ) : (
                          nextEntry[1]
                        )}
                      </td>
                    </>
                  ) : (
                    <>
                      <td></td>
                      <td></td>
                    </>
                  )}
                </tr>
              )
            );
          });
        })}
      </tbody>
      
          </table>
        </div>
      )}

     {/* Attachment Analysis */}
      {attachmentsResult === null ? (
            <div>
            </div>
        ) : (
            (Object.keys(attachmentsResult).length > 0 && 
            ((attachmentsResult.suspicious_files && Object.keys(attachmentsResult.suspicious_files).length > 0) || 
            (attachmentsResult.suspicious_links && attachmentsResult.suspicious_links.length > 0))) ? (
                <div className="window3">
                    <h2 style={{textAlign:"center"}}>Attachment Analysis</h2>
                    <table className="styled-table">
                        <thead>
                            <tr>
                                <th>Categories</th>
                                <th>Item</th>
                            </tr>
                        </thead>
                        <tbody>
                            {attachmentsResult.suspicious_files && Object.keys(attachmentsResult.suspicious_files).length > 0 ? (
                                Object.keys(attachmentsResult.suspicious_files).map((file, index) => (
                                    <tr key={index}>
                                        <td>Suspicious File:</td>
                                        <td>{file} ({attachmentsResult.suspicious_files[file].category})</td>
                                    </tr>
                                ))
                            ) : null}
                            {attachmentsResult.suspicious_links && attachmentsResult.suspicious_links.length > 0 ? (
                                attachmentsResult.suspicious_links.map((link, index) => (
                                  <tr key={index}>
                                  <td>Suspicious Link:</td>
                                  <td>
                                    <a href={link} target="_blank" rel="noopener noreferrer" className="sandbox-link">
                                      Open in Sandbox: {link}
                                    </a>
                                  </td>
                                </tr>
                                ))
                            ) : null}
                        </tbody>
                    </table>
                </div>
            ) : (
                <div className="window3">
                    <h2>Attachment Analysis</h2>
                    <p>No attachments found.</p>
                </div>
            )
        )}


      {/* Header Details */}
      {parsedData && Object.keys(parsedData).length > 0 && (
        <>
          <div id='parsed-data-div' className="window parsed-data">
            <div className="search-filter">
              <input
                type="text"
                placeholder="Search headers..."
                value={searchTerm}
                onChange={handleSearchChange}
              />
            </div>
            <h2>Header Segment</h2>
            <table>
              <thead>
                <tr>
                  <th>Header Name</th>
                  <th>Header Value</th>
                </tr>
              </thead>
              <tbody>
                {filteredData.map(([key, value], index) => (
                  <tr key={index}>
                    <td className="key">{key}</td>
                    <td className="value">{value}</td>
                  </tr>
                ))}
              </tbody>
            </table>
            
          </div>
          <div >
          <div class="spacer"></div>
      <button className='ScrollButton' onClick={ScrollToBottom}>Scroll to Header ↓</button>
    </div>
        </>
      )}

      <div className="fixed-bottom">
        <h2>Contributors</h2>
        <div className="row">
          <div className="col">
            <img src={require('./assets/images/contributor01.png')} alt="Contributor 01" className="contributor-img" />
          </div>
          <div className='col'>...</div>
          <div className='col'>...</div>
          <div className='col'>...</div>
        </div>
      </div>

      {isParsing && <Loader />}
    </div>
  );
}

export default App;
