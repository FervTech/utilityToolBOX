const fs = require('fs');
const path = require('path');

console.log('Building Utility Toolbox...');

// Create dist folder
const distPath = path.join(__dirname, 'dist');
if (!fs.existsSync(distPath)) {
  fs.mkdirSync(distPath, { recursive: true });
}

// Copy public folder contents to dist
const publicPath = path.join(__dirname, 'public');
if (fs.existsSync(publicPath)) {
  copyFolder(publicPath, distPath);
  console.log('✅ Copied public/ to dist/');
} else {
  console.log('⚠️ No public/ folder found');

  // Create basic structure if public doesn't exist
  const folders = ['dist/js', 'dist/css'];
  folders.forEach(folder => {
    if (!fs.existsSync(folder)) {
      fs.mkdirSync(folder, { recursive: true });
    }
  });

  // Create minimal files
  fs.writeFileSync('dist/index.html', `
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>Utility Toolbox</title>
      <link rel="stylesheet" href="css/style.css">
    </head>
    <body>
      <h1>Utility Toolbox</h1>
      <p>Your tools are ready!</p>
      <script src="js/app.js"></script>
    </body>
    </html>
  `);

  fs.writeFileSync('dist/css/style.css', 'body { font-family: Arial, sans-serif; margin: 20px; }');
  fs.writeFileSync('dist/js/app.js', 'console.log("Utility Toolbox loaded!");');
}

function copyFolder(src, dest) {
  const files = fs.readdirSync(src);

  for (const file of files) {
    const srcPath = path.join(src, file);
    const destPath = path.join(dest, file);

    if (fs.statSync(srcPath).isDirectory()) {
      if (!fs.existsSync(destPath)) {
        fs.mkdirSync(destPath, { recursive: true });
      }
      copyFolder(srcPath, destPath);
    } else {
      fs.copyFileSync(srcPath, destPath);
    }
  }
}

console.log('✅ Build complete! Files are in dist/');
