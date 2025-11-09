import React, { useEffect, useState } from 'react';
import ReactDOM from 'react-dom';

const IdentitiesView = () => {
  const [identities, setIdentities] = useState([]);

  useEffect(() => {
    fetch("/en-US/identities", {
      headers: {
        "X-Requested-With": "XMLHttpRequest"
      },
      credentials: "same-origin"
    })
    .then(res => res.json())
    .then(data => setIdentities(data))
    .catch(err => console.error("Error:", err));
  }, []);

  return (
    <div>
      <h1>Identities</h1>
      <ul>
        {identities.map((id, index) => (
          <li key={index}>{id.name} - {id.role}</li>
        ))}
      </ul>
    </div>
  );
};

ReactDOM.render(<IdentitiesView />, document.getElementById('root'));
