const { merge } = require('webpack-merge');
const common = require('./webpack.config.prod.js');

module.exports = merge(common, {
  mode: 'development',
  devtool: 'inline-source-map',
  devServer: {
    static: './dist',
    hot: true,
    port: 3000
  }
});
