import React from 'react';
import './loader.css'; // Import the CSS for styling the loader
import loaderImage from './assets/images/Loader.gif'; // Path to your loader PNG image

const Loader = () => (
    <div class="loader">
    <div class="smoke"></div>
    <div class="loader-wrapper">
      {/* <div class="loader-circle"></div> */}
    <img src={loaderImage} alt="Loading..." />
  
  </div>
  </div>
);

export default Loader;
