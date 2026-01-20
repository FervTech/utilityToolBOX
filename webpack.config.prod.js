const path = require('path');
const HtmlWebpackPlugin = require('html-webpack-plugin');

module.exports = {
  mode: 'production',

  // CHANGE THIS: Use your actual entry file
  entry: './app.js',  // or './src/app.js' or whatever your path is

  output: {
    path: path.resolve(__dirname, 'dist'),
    filename: 'bundle.js'  // This will be your output file
  },

  plugins: [
    new HtmlWebpackPlugin({
      template: './index.html',  // If you have an HTML file
      // OR if you don't have HTML:
      templateContent: `
        <!DOCTYPE html>
        <html>
          <head>
            <meta charset="utf-8">
            <title>My App</title>
          </head>
          <body>
            <div id="app"></div>
            <script src="bundle.js"></script>
          </body>
        </html>
      `
    })
  ],

  stats: {
    errorDetails: true,
    children: true
  }
};
