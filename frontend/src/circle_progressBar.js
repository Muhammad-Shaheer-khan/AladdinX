import React from 'react';

const ProgressBar = ({ percentage, sum }) => {
  const cleanPercentage = (percentage) => {
    const isNegativeOrNaN = !Number.isFinite(+percentage) || percentage < 0;
    const isTooHigh = percentage > sum;
    return isNegativeOrNaN ? 0 : isTooHigh ? sum : +percentage;
  };

  const r = 70;
  const circ = 2 * Math.PI * r;
  const cleanedPercentage = cleanPercentage(percentage);
  const strokePct = ((sum - cleanedPercentage) * circ) / sum;

  return (
    <svg width="200" height="200">
      {/* Base circle in white */}
      <circle
        r={r}
        cx={100}
        cy={100}
        fill="transparent"
        stroke="Grey" // Base color in white
        strokeWidth="1rem"
        strokeDasharray={circ}
        strokeDashoffset={0}
        strokeLinecap="round"
        transform={`rotate(-90 ${100} ${100})`} // rotate the circle to start at 12 o'clock
      />
      {/* Overlay with green or red depending on the percentage */}
      <circle
        r={r}
        cx={100}
        cy={100}
        fill="transparent"
        stroke={cleanedPercentage === 0 ? "lightgreen" : cleanedPercentage < sum ? "red" : "lightgreen"} // Green when percentage is 0, otherwise red
        strokeWidth="1rem"
        strokeDasharray={circ}
        strokeDashoffset={cleanedPercentage === 0 ? 0 : strokePct}
        strokeLinecap="round"
        transform={`rotate(-90 ${100} ${100})`} // rotate the circle to start at 12 o'clock
      />
      <text
        x="50%"
        y="50%"
        dominantBaseline="central"
        textAnchor="middle"
        fill="#FFFFFF"
        fontSize={"1.5em"}
      >
        {cleanedPercentage.toFixed(0)}/{sum}
      </text>
      
      <text
          x="50%"
          y="96%"
          dominantBaseline="central"
          textAnchor="middle"
          fill="#FFFFFF"
          fontSize={"1em"}
        >
          Malicious Reports
        </text>
    </svg>
    
  );
};

export default ProgressBar;