const path = require('path');

module.exports = {
  entry: './appserver/static/js/components/identities/IdentitiesView.jsx',
  output: {
    path: path.resolve(__dirname, 'appserver/static/js/build'),
    filename: 'identities.bundle.js'
  },
  mode: 'production',
  module: {
    rules: [
      {
        test: /\.jsx?$/,
        use: 'babel-loader',
        exclude: /node_modules/
      }
    ]
  },
  resolve: {
    extensions: ['.js', '.jsx']
  }
};
