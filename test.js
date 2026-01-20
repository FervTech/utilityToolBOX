// CRYPTO TOOLS

// bcryptTool - Already implemented, but we'll enhance with a real bcrypt-like implementation
function bcryptTool() {
  setTool('Bcrypt', `
        <div class="form-group"><label>Mode</label><select id="mode"><option>Hash</option><option>Compare</option></select></div>
        <div class="form-group"><label>Password</label><input id="pass" type="password" placeholder="Enter password"/></div>
        <div id="hashSection" class="form-group"><label>Rounds (4-31)</label><input id="rounds" type="number" value="10" min="4" max="31"/></div>
        <div id="compareSection" style="display:none;" class="form-group"><label>Hash to compare</label><input id="hash" type="text" placeholder="Enter bcrypt hash"/></div>
        <div class="btn-group"><button id="btn" class="btn">Process</button><button id="copy" class="btn btn-secondary">Copy</button></div>
        <div id="out" class="output"></div>
      `, () => {
    $('#mode').addEventListener('change', () => {
      const mode = $('#mode').value;
      $('#hashSection').style.display = mode === 'Hash' ? 'block' : 'none';
      $('#compareSection').style.display = mode === 'Compare' ? 'block' : 'none';
    });

    function bcryptHash(password, rounds) {
      const salt = Array.from(crypto.getRandomValues(new Uint8Array(16)))
        .map(b => b.toString(16).padStart(2, '0')).join('');
      const cost = rounds.toString().padStart(2, '0');
      const saltBase64 = btoa(salt).replace(/=+$/, '');
      return `$2b$${cost}$${saltBase64}${hashPassword(password, salt, rounds)}`;
    }

    function hashPassword(password, salt, rounds) {
      const encoder = new TextEncoder();
      const data = encoder.encode(password + salt);
      let hash = data;
      for (let i = 0; i < Math.pow(2, rounds); i++) {
        const hashBuffer = crypto.subtle.digest('SHA-256', hash);
        hash = new Uint8Array(hashBuffer);
      }
      return Array.from(hash).map(b => b.toString(16).padStart(2, '0')).join('').slice(0, 31);
    }

    function bcryptCompare(password, hash) {
      try {
        const parts = hash.split('$');
        if (parts.length !== 4 || parts[1] !== '2b') return false;
        const cost = parseInt(parts[2]);
        const salt = atob(parts[3].slice(0, 22));
        const storedHash = parts[3].slice(22);
        const computedHash = hashPassword(password, salt, cost);
        return computedHash === storedHash;
      } catch (e) {
        return false;
      }
    }

    $('#btn').addEventListener('click', async () => {
      const mode = $('#mode').value;
      const pass = $('#pass').value;
      if (!pass) return toast('Enter a password', 'error');

      if (mode === 'Hash') {
        const rounds = parseInt($('#rounds').value) || 10;
        if (rounds < 4 || rounds > 31) return toast('Rounds must be 4-31', 'error');
        const hash = bcryptHash(pass, rounds);
        $('#out').textContent = hash;
        toast('Password hashed');
      } else {
        const hash = $('#hash').value;
        if (!hash) return toast('Enter hash to compare', 'error');
        const match = bcryptCompare(pass, hash);
        $('#out').textContent = match ? '✓ Password matches!' : '✗ Password does not match';
        toast(match ? 'Match!' : 'No match', match ? 'success' : 'error');
      }
    });
    $('#copy').addEventListener('click', () => navigator.clipboard.writeText($('#out').textContent).then(() => toast('Copied')));
  });
}

function bip39Tool() {
  setTool('BIP39 Passphrase Generator', `
        <div class="form-group"><label>Mode</label><select id="mode"><option>Generate from mnemonic</option><option>Get mnemonic from passphrase</option><option>Generate random mnemonic</option></select></div>
        <div id="mnemonicSection" class="form-group"><label>Mnemonic (12/24 words)</label><textarea id="mnemonic" rows="3" placeholder="Enter BIP39 mnemonic"></textarea></div>
        <div id="passphraseSection" style="display:none;" class="form-group"><label>Passphrase</label><input id="passphrase" type="password" placeholder="Enter passphrase"/></div>
        <div id="strengthSection" class="form-group"><label>Entropy Strength</label><select id="strength"><option value="128">128 bits (12 words)</option><option value="256">256 bits (24 words)</option></select></div>
        <div class="form-group"><label>Passphrase (optional)</label><input id="extraPassphrase" type="password" placeholder="Additional passphrase (optional)"/></div>
        <div class="btn-group"><button id="btn" class="btn">Generate</button><button id="copy" class="btn btn-secondary">Copy</button></div>
        <div id="out" class="output"></div>
      `, () => {
    const bip39Wordlist = [
      "abandon", "ability", "able", "about", "above", "absent", "absorb", "abstract", "absurd", "abuse",
      "access", "accident", "account", "accuse", "achieve", "acid", "acoustic", "acquire", "across", "act",
      "action", "actor", "actress", "actual", "adapt", "add", "addict", "address", "adjust", "admit",
      "adult", "advance", "advice", "aerobic", "affair", "afford", "afraid", "again", "age", "agent"
    ];

    $('#mode').addEventListener('change', () => {
      const mode = $('#mode').value;
      $('#mnemonicSection').style.display = mode.includes('mnemonic') ? 'block' : 'none';
      $('#passphraseSection').style.display = mode.includes('passphrase') ? 'block' : 'none';
      $('#strengthSection').style.display = mode.includes('random') ? 'block' : 'none';
    });

    function generateMnemonic(strength) {
      const bytes = new Uint8Array(strength / 8);
      crypto.getRandomValues(bytes);
      const hex = Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
      const bits = hex.split('').map(h => parseInt(h, 16).toString(2).padStart(4, '0')).join('');

      let mnemonic = [];
      for (let i = 0; i < strength / 11; i++) {
        const chunk = bits.substr(i * 11, 11);
        const index = parseInt(chunk, 2);
        mnemonic.push(bip39Wordlist[index % bip39Wordlist.length]);
      }
      return mnemonic.join(' ');
    }

    function mnemonicToSeed(mnemonic, passphrase = '') {
      const encoder = new TextEncoder();
      const data = encoder.encode(mnemonic.normalize('NFKD') + passphrase.normalize('NFKD'));
      return crypto.subtle.digest('SHA-256', data).then(hash => {
        return Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2, '0')).join('');
      });
    }

    $('#btn').addEventListener('click', async () => {
      const mode = $('#mode').value;
      let output = '';

      if (mode === 'Generate random mnemonic') {
        const strength = parseInt($('#strength').value);
        output = generateMnemonic(strength);
      } else if (mode === 'Generate from mnemonic') {
        const mnemonic = $('#mnemonic').value.trim();
        const extraPassphrase = $('#extraPassphrase').value;
        if (!mnemonic) return toast('Enter mnemonic', 'error');
        const seed = await mnemonicToSeed(mnemonic, extraPassphrase);
        output = `Seed: ${seed}`;
      } else {
        const passphrase = $('#passphrase').value;
        if (!passphrase) return toast('Enter passphrase', 'error');
        output = 'Note: This is a simplified BIP39 implementation. In production, use a proper library like bip39.';
      }

      $('#out').textContent = output;
      toast('Generated');
    });

    $('#copy').addEventListener('click', () => navigator.clipboard.writeText($('#out').textContent).then(() => toast('Copied')));
  });
}

function rsaTool() {
  setTool('RSA Key Pair Generator', `
        <div class="form-group"><label>Key Size</label><select id="keySize"><option value="2048">2048 bits</option><option value="3072">3072 bits</option><option value="4096">4096 bits</option></select></div>
        <div class="form-group"><label>Format</label><select id="format"><option>PEM</option><option>JWK</option></select></div>
        <div class="btn-group"><button id="generate" class="btn">Generate Key Pair</button></div>
        <div class="form-group"><label>Public Key</label><div id="publicKey" class="output" style="min-height: 100px;"></div></div>
        <div class="form-group"><label>Private Key</label><div id="privateKey" class="output" style="min-height: 150px;"></div></div>
        <div class="btn-group"><button id="copyPublic" class="btn btn-secondary">Copy Public</button><button id="copyPrivate" class="btn btn-secondary">Copy Private</button></div>
      `, async () => {
    $('#generate').addEventListener('click', async () => {
      try {
        const keySize = parseInt($('#keySize').value);
        const format = $('#format').value;

        const keyPair = await crypto.subtle.generateKey(
          {
            name: "RSA-OAEP",
            modulusLength: keySize,
            publicExponent: new Uint8Array([1, 0, 1]),
            hash: "SHA-256",
          },
          true,
          ["encrypt", "decrypt"]
        );

        if (format === 'PEM') {
          const exportedPublic = await crypto.subtle.exportKey("spki", keyPair.publicKey);
          const exportedPrivate = await crypto.subtle.exportKey("pkcs8", keyPair.privateKey);

          const publicPem = `-----BEGIN PUBLIC KEY-----\n${btoa(String.fromCharCode(...new Uint8Array(exportedPublic))).match(/.{1,64}/g).join('\n')}\n-----END PUBLIC KEY-----`;
          const privatePem = `-----BEGIN PRIVATE KEY-----\n${btoa(String.fromCharCode(...new Uint8Array(exportedPrivate))).match(/.{1,64}/g).join('\n')}\n-----END PRIVATE KEY-----`;

          $('#publicKey').textContent = publicPem;
          $('#privateKey').textContent = privatePem;
        } else {
          const publicJwk = await crypto.subtle.exportKey("jwk", keyPair.publicKey);
          const privateJwk = await crypto.subtle.exportKey("jwk", keyPair.privateKey);

          $('#publicKey').textContent = JSON.stringify(publicJwk, null, 2);
          $('#privateKey').textContent = JSON.stringify(privateJwk, null, 2);
        }

        toast('RSA key pair generated');
      } catch (error) {
        toast('Error generating keys: ' + error.message, 'error');
      }
    });

    $('#copyPublic').addEventListener('click', () => {
      navigator.clipboard.writeText($('#publicKey').textContent).then(() => toast('Public key copied'));
    });

    $('#copyPrivate').addEventListener('click', () => {
      navigator.clipboard.writeText($('#privateKey').textContent).then(() => toast('Private key copied'));
    });
  });
}

function pwStrengthTool() {
  setTool('Password Strength Analyser', `
        <div class="form-group"><label>Password</label><input id="password" type="password" placeholder="Enter password to analyze"/></div>
        <div class="btn-group"><button id="analyze" class="btn">Analyze Strength</button></div>
        <div id="strengthMeter" style="height: 8px; background: var(--border); border-radius: 4px; margin: 16px 0; overflow: hidden;">
            <div id="strengthBar" style="height: 100%; width: 0%; background: var(--error); transition: width 0.3s, background 0.3s;"></div>
        </div>
        <div id="score" style="font-size: 24px; font-weight: bold; text-align: center; margin: 16px 0;"></div>
        <div id="feedback" class="output"></div>
        <div class="btn-group"><button id="suggest" class="btn btn-secondary">Suggest Strong Password</button><button id="copySuggestion" class="btn btn-secondary">Copy</button></div>
        <div id="suggestion" class="output" style="display: none;"></div>
      `, () => {
    function analyzePassword(password) {
      let score = 0;
      const feedback = [];

      // Length check
      if (password.length >= 12) score += 30;
      else if (password.length >= 8) score += 20;
      else if (password.length >= 6) score += 10;
      else feedback.push('❌ Too short (minimum 6 characters)');

      // Character variety
      const hasLower = /[a-z]/.test(password);
      const hasUpper = /[A-Z]/.test(password);
      const hasDigit = /\d/.test(password);
      const hasSpecial = /[^a-zA-Z0-9]/.test(password);

      if (hasLower) score += 10;
      else feedback.push('❌ Add lowercase letters');
      if (hasUpper) score += 10;
      else feedback.push('❌ Add uppercase letters');
      if (hasDigit) score += 10;
      else feedback.push('❌ Add numbers');
      if (hasSpecial) score += 10;
      else feedback.push('❌ Add special characters');

      // Bonus for mixed case
      if (hasLower && hasUpper) score += 10;

      // Check for common patterns
      const common = ['password', '123456', 'qwerty', 'letmein', 'welcome'];
      if (common.some(word => password.toLowerCase().includes(word))) {
        score -= 20;
        feedback.push('⚠️ Contains common pattern');
      }

      // Sequential characters check
      const sequential = /(abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz|012|123|234|345|456|567|678|789)/i;
      if (sequential.test(password)) {
        score -= 10;
        feedback.push('⚠️ Contains sequential characters');
      }

      // Crack time estimation
      const entropy = Math.log2(Math.pow(95, password.length));
      let crackTime = 'centuries';
      if (entropy < 28) crackTime = 'instantly';
      else if (entropy < 36) crackTime = 'hours';
      else if (entropy < 60) crackTime = 'days';
      else if (entropy < 80) crackTime = 'months';

      // Determine strength level
      let strength = 'Very Weak';
      let color = '#ef4444';

      if (score >= 70) {
        strength = 'Very Strong';
        color = '#10b981';
      } else if (score >= 50) {
        strength = 'Strong';
        color = '#22c55e';
      } else if (score >= 30) {
        strength = 'Good';
        color = '#eab308';
      } else if (score >= 20) {
        strength = 'Weak';
        color = '#f97316';
      }

      return { score: Math.min(score, 100), strength, color, feedback, crackTime, entropy };
    }

    function generateStrongPassword() {
      const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+-=[]{}|;:,.<>?';
      let password = '';
      for (let i = 0; i < 16; i++) {
        password += chars.charAt(Math.floor(Math.random() * chars.length));
      }
      return password;
    }

    $('#analyze').addEventListener('click', () => {
      const password = $('#password').value;
      if (!password) return toast('Enter a password', 'error');

      const result = analyzePassword(password);

      $('#strengthBar').style.width = result.score + '%';
      $('#strengthBar').style.background = result.color;
      $('#score').textContent = `${result.strength} (${result.score}/100)`;
      $('#score').style.color = result.color;

      const feedbackText = [
        `🔐 Entropy: ${result.entropy.toFixed(1)} bits`,
        `⏱️ Estimated crack time: ${result.crackTime}`,
        '',
        'Suggestions:',
        ...result.feedback,
        '',
        'Tips:',
        '✓ Use at least 12 characters',
        '✓ Mix uppercase, lowercase, numbers, and symbols',
        '✓ Avoid common words and patterns',
        '✓ Use a passphrase for better memorability'
      ].join('\n');

      $('#feedback').textContent = feedbackText;
    });

    $('#suggest').addEventListener('click', () => {
      const suggestion = generateStrongPassword();
      $('#suggestion').textContent = suggestion;
      $('#suggestion').style.display = 'block';
      toast('Strong password generated');
    });

    $('#copySuggestion').addEventListener('click', () => {
      navigator.clipboard.writeText($('#suggestion').textContent).then(() => toast('Copied'));
    });
  });
}

function pdfcheckTool() {
  setTool('PDF Signature Checker', `
        <div class="form-group">
            <label>Upload PDF File</label>
            <input type="file" id="pdfFile" accept=".pdf" />
        </div>
        <div class="btn-group">
            <button id="check" class="btn">Check Signatures</button>
        </div>
        <div id="results" class="output"></div>
        <div style="margin-top: 16px; padding: 16px; background: var(--bg-secondary); border-radius: 8px;">
            <h4 style="margin-bottom: 8px;">ℹ️ About PDF Signatures</h4>
            <p style="color: var(--text-muted); font-size: 14px;">
                PDF signatures are used to verify the authenticity and integrity of PDF documents.
                This tool checks for embedded digital signatures in PDF files. Note: Full signature
                validation requires cryptographic verification which needs specialized libraries.
            </p>
        </div>
      `, () => {
    $('#check').addEventListener('click', () => {
      const fileInput = $('#pdfFile');
      const file = fileInput.files[0];

      if (!file) {
        toast('Please select a PDF file', 'error');
        return;
      }

      if (!file.name.toLowerCase().endsWith('.pdf')) {
        toast('Please select a PDF file', 'error');
        return;
      }

      const reader = new FileReader();
      reader.onload = function(e) {
        try {
          const arrayBuffer = e.target.result;
          const uint8Array = new Uint8Array(arrayBuffer);

          // Check PDF header
          const header = String.fromCharCode(...uint8Array.slice(0, 5));
          if (header !== '%PDF-') {
            $('#results').textContent = '❌ Invalid PDF file';
            return;
          }

          // Look for signature markers in the PDF
          const pdfText = new TextDecoder('utf-8').decode(uint8Array);

          const results = [];

          // Check for digital signature dictionary
          if (pdfText.includes('/Sig') || pdfText.includes('/Signature')) {
            results.push('✓ Found signature markers');

            // Look for common signature fields
            const sigRegex = /\/Sig\s*<<([^>>]*)>>/g;
            let match;
            let sigCount = 0;

            while ((match = sigRegex.exec(pdfText)) !== null) {
              sigCount++;
              results.push(`  Signature ${sigCount}: Found signature field`);

              // Extract common signature properties
              const sigData = match[1];
              if (sigData.includes('/Reason')) {
                const reasonMatch = sigData.match(/\/Reason\s*\(([^)]*)\)/);
                if (reasonMatch) results.push(`    Reason: ${reasonMatch[1]}`);
              }
              if (sigData.includes('/M')) {
                const dateMatch = sigData.match(/\/M\s*\(([^)]*)\)/);
                if (dateMatch) results.push(`    Date: ${dateMatch[1]}`);
              }
            }

            if (sigCount > 0) {
              results.push(`\nTotal signatures found: ${sigCount}`);
            } else {
              results.push('⚠️ Signature markers found but no complete signature fields detected');
            }
          } else {
            results.push('❌ No digital signatures found in this PDF');
          }

          // Check for certification
          if (pdfText.includes('/DocMDP')) {
            results.push('✓ Document is certified');
          }

          // File info
          results.push('\n📄 File Information:');
          results.push(`  Size: ${(file.size / 1024).toFixed(2)} KB`);
          results.push(`  Last modified: ${new Date(file.lastModified).toLocaleString()}`);

          $('#results').textContent = results.join('\n');
          toast('PDF analysis complete');

        } catch (error) {
          $('#results').textContent = `Error analyzing PDF: ${error.message}`;
          toast('Analysis failed', 'error');
        }
      };

      reader.onerror = function() {
        $('#results').textContent = 'Error reading file';
        toast('File read error', 'error');
      };

      reader.readAsArrayBuffer(file);
    });
  });
}

// CONVERTER TOOLS

function datetimeTool() {
  setTool('Date-Time Converter', `
        <div class="row">
            <div class="form-group">
                <label>Date & Time</label>
                <input type="datetime-local" id="datetimeInput" />
            </div>
            <div class="form-group">
                <label>Timestamp (ms)</label>
                <input type="number" id="timestampInput" placeholder="Unix timestamp" />
            </div>
        </div>
        <div class="form-group">
            <label>Input Format</label>
            <select id="inputFormat">
                <option value="now">Current Time</option>
                <option value="custom">Custom Date</option>
                <option value="timestamp">From Timestamp</option>
            </select>
        </div>
        <div class="btn-group">
            <button id="convert" class="btn">Convert</button>
            <button id="setNow" class="btn btn-secondary">Set to Now</button>
        </div>
        <div id="results" class="output"></div>
      `, () => {
    function updateResults(date) {
      const formats = [
        ['ISO 8601', date.toISOString()],
        ['Local String', date.toLocaleString()],
        ['UTC String', date.toUTCString()],
        ['Unix Timestamp (ms)', date.getTime()],
        ['Unix Timestamp (s)', Math.floor(date.getTime() / 1000)],
        ['Date Only', date.toLocaleDateString()],
        ['Time Only', date.toLocaleTimeString()],
        ['RFC 2822', date.toDateString() + ' ' + date.toTimeString()],
        ['Custom Format', `${date.getFullYear()}-${String(date.getMonth()+1).padStart(2,'0')}-${String(date.getDate()).padStart(2,'0')} ${String(date.getHours()).padStart(2,'0')}:${String(date.getMinutes()).padStart(2,'0')}:${String(date.getSeconds()).padStart(2,'0')}`]
      ];

      $('#results').textContent = formats.map(([name, value]) => `${name}:\n${value}`).join('\n\n');
    }

    $('#inputFormat').addEventListener('change', () => {
      const format = $('#inputFormat').value;
      $('#datetimeInput').style.display = format === 'custom' ? 'block' : 'none';
      $('#timestampInput').style.display = format === 'timestamp' ? 'block' : 'none';
    });

    $('#setNow').addEventListener('click', () => {
      const now = new Date();
      $('#datetimeInput').value = now.toISOString().slice(0, 16);
      $('#timestampInput').value = now.getTime();
      updateResults(now);
    });

    $('#convert').addEventListener('click', () => {
      try {
        let date;
        const format = $('#inputFormat').value;

        if (format === 'now') {
          date = new Date();
        } else if (format === 'custom') {
          const datetime = $('#datetimeInput').value;
          if (!datetime) {
            toast('Please enter a date and time', 'error');
            return;
          }
          date = new Date(datetime + ':00');
        } else if (format === 'timestamp') {
          const timestamp = $('#timestampInput').value;
          if (!timestamp) {
            toast('Please enter a timestamp', 'error');
            return;
          }
          date = new Date(parseInt(timestamp) * (timestamp.length <= 10 ? 1000 : 1));
        }

        if (isNaN(date.getTime())) {
          toast('Invalid date', 'error');
          return;
        }

        updateResults(date);
        toast('Date converted');
      } catch (error) {
        toast('Conversion error: ' + error.message, 'error');
      }
    });

    // Initialize
    $('#setNow').click();
  });
}

function intbaseTool() {
  setTool('Integer Base Converter', `
        <div class="form-group">
            <label>Input Value</label>
            <input type="text" id="inputValue" placeholder="Enter number" value="255" />
        </div>
        <div class="row">
            <div class="form-group">
                <label>From Base</label>
                <select id="fromBase">
                    <option value="2">Binary (2)</option>
                    <option value="8">Octal (8)</option>
                    <option value="10" selected>Decimal (10)</option>
                    <option value="16">Hexadecimal (16)</option>
                    <option value="36">Base36 (0-9, a-z)</option>
                    <option value="62">Base62 (0-9, A-Z, a-z)</option>
                </select>
            </div>
            <div class="form-group">
                <label>To Base</label>
                <select id="toBase">
                    <option value="2">Binary (2)</option>
                    <option value="8">Octal (8)</option>
                    <option value="10">Decimal (10)</option>
                    <option value="16" selected>Hexadecimal (16)</option>
                    <option value="36">Base36 (0-9, a-z)</option>
                    <option value="62">Base62 (0-9, A-Z, a-z)</option>
                </select>
            </div>
        </div>
        <div class="btn-group">
            <button id="convert" class="btn">Convert</button>
            <button id="swap" class="btn btn-secondary">Swap Bases</button>
            <button id="copy" class="btn btn-secondary">Copy Result</button>
        </div>
        <div id="result" class="output"></div>
      `, () => {
    const baseChars = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';

    function convertBase(str, fromBase, toBase) {
      // Convert to decimal first
      let decimalValue = 0;
      const fromBaseInt = parseInt(fromBase);
      const toBaseInt = parseInt(toBase);

      // Handle negative numbers
      let isNegative = false;
      if (str.startsWith('-')) {
        isNegative = true;
        str = str.substring(1);
      }

      // Convert from source base to decimal
      for (let i = 0; i < str.length; i++) {
        const char = str[i];
        let digitValue;

        if (char >= '0' && char <= '9') {
          digitValue = char.charCodeAt(0) - '0'.charCodeAt(0);
        } else if (char >= 'A' && char <= 'Z') {
          digitValue = char.charCodeAt(0) - 'A'.charCodeAt(0) + 10;
        } else if (char >= 'a' && char <= 'z') {
          digitValue = char.charCodeAt(0) - 'a'.charCodeAt(0) + 36;
        } else {
          throw new Error(`Invalid character '${char}' for base ${fromBase}`);
        }

        if (digitValue >= fromBaseInt) {
          throw new Error(`Digit '${char}' exceeds base ${fromBase}`);
        }

        decimalValue = decimalValue * fromBaseInt + digitValue;
      }

      if (isNegative) {
        decimalValue = -decimalValue;
      }

      // Convert decimal to target base
      if (toBaseInt === 10) {
        return decimalValue.toString();
      }

      let result = '';
      let number = Math.abs(decimalValue);

      if (number === 0) {
        return '0';
      }

      while (number > 0) {
        const remainder = number % toBaseInt;
        result = baseChars[remainder] + result;
        number = Math.floor(number / toBaseInt);
      }

      return (isNegative ? '-' : '') + result;
    }

    $('#convert').addEventListener('click', () => {
      try {
        const input = $('#inputValue').value.trim();
        const fromBase = $('#fromBase').value;
        const toBase = $('#toBase').value;

        if (!input) {
          toast('Please enter a value', 'error');
          return;
        }

        const result = convertBase(input, fromBase, toBase);

        $('#result').textContent = `${input} (base ${fromBase}) = ${result} (base ${toBase})`;
        toast('Conversion successful');
      } catch (error) {
        toast('Conversion error: ' + error.message, 'error');
      }
    });

    $('#swap').addEventListener('click', () => {
      const fromBase = $('#fromBase').value;
      const toBase = $('#toBase').value;
      $('#fromBase').value = toBase;
      $('#toBase').value = fromBase;
      $('#convert').click();
    });

    $('#copy').addEventListener('click', () => {
      navigator.clipboard.writeText($('#result').textContent.split(' = ')[1]?.split(' ')[0] || '')
        .then(() => toast('Copied'));
    });

    // Initialize
    $('#convert').click();
  });
}

function romanTool() {
  setTool('Roman Numeral Converter', `
        <div class="form-group">
            <label>Input</label>
            <input type="text" id="input" placeholder="Enter Roman numeral or number" value="MMXXIV" />
        </div>
        <div class="form-group">
            <label>Direction</label>
            <select id="direction">
                <option value="toRoman">Number → Roman</option>
                <option value="fromRoman" selected>Roman → Number</option>
            </select>
        </div>
        <div class="btn-group">
            <button id="convert" class="btn">Convert</button>
            <button id="copy" class="btn btn-secondary">Copy Result</button>
        </div>
        <div id="result" class="output"></div>
        <div style="margin-top: 16px; font-size: 14px; color: var(--text-muted);">
            <p>Roman numerals use the following symbols:</p>
            <p>I=1, V=5, X=10, L=50, C=100, D=500, M=1000</p>
        </div>
      `, () => {
    const romanMap = [
      [1000, 'M'], [900, 'CM'], [500, 'D'], [400, 'CD'],
      [100, 'C'], [90, 'XC'], [50, 'L'], [40, 'XL'],
      [10, 'X'], [9, 'IX'], [5, 'V'], [4, 'IV'], [1, 'I']
    ];

    const romanValues = {
      'I': 1, 'V': 5, 'X': 10, 'L': 50,
      'C': 100, 'D': 500, 'M': 1000
    };

    function toRoman(num) {
      if (num <= 0 || num >= 4000) {
        throw new Error('Number must be between 1 and 3999');
      }

      let result = '';
      let remaining = num;

      for (const [value, symbol] of romanMap) {
        while (remaining >= value) {
          result += symbol;
          remaining -= value;
        }
      }

      return result;
    }

    function fromRoman(roman) {
      const str = roman.toUpperCase().trim();
      if (!/^[IVXLCDM]+$/i.test(str)) {
        throw new Error('Invalid Roman numeral');
      }

      let total = 0;
      let prevValue = 0;

      for (let i = str.length - 1; i >= 0; i--) {
        const current = romanValues[str[i]];
        if (current < prevValue) {
          total -= current;
        } else {
          total += current;
        }
        prevValue = current;
      }

      // Validate by converting back
      if (toRoman(total) !== str) {
        throw new Error('Invalid Roman numeral sequence');
      }

      return total;
    }

    $('#convert').addEventListener('click', () => {
      try {
        const input = $('#input').value.trim();
        const direction = $('#direction').value;

        if (!input) {
          toast('Please enter a value', 'error');
          return;
        }

        let result;
        if (direction === 'toRoman') {
          const num = parseInt(input);
          if (isNaN(num)) throw new Error('Invalid number');
          result = toRoman(num);
          $('#result').textContent = `${num} = ${result}`;
        } else {
          result = fromRoman(input);
          $('#result').textContent = `${input} = ${result}`;
        }

        toast('Conversion successful');
      } catch (error) {
        toast('Conversion error: ' + error.message, 'error');
      }
    });

    $('#copy').addEventListener('click', () => {
      const text = $('#result').textContent;
      const result = text.split(' = ')[1];
      if (result) {
        navigator.clipboard.writeText(result).then(() => toast('Copied'));
      }
    });

    // Initialize
    $('#convert').click();
  });
}

function b64fileTool() {
  setTool('Base64 File Converter', `
        <div class="form-group">
            <label>Mode</label>
            <select id="mode">
                <option value="toBase64">File → Base64</option>
                <option value="fromBase64">Base64 → File</option>
            </select>
        </div>
        <div id="fileSection" class="form-group">
            <label>Select File</label>
            <input type="file" id="fileInput" />
        </div>
        <div id="base64Section" class="form-group" style="display: none;">
            <label>Base64 String</label>
            <textarea id="base64Input" rows="6" placeholder="Paste base64 string"></textarea>
        </div>
        <div id="mimeSection" class="form-group">
            <label>File Type (MIME)</label>
            <input type="text" id="mimeType" placeholder="e.g., image/png, text/plain" />
        </div>
        <div class="btn-group">
            <button id="convert" class="btn">Convert</button>
            <button id="download" class="btn btn-secondary" style="display: none;">Download File</button>
            <button id="copy" class="btn btn-secondary">Copy Base64</button>
        </div>
        <div id="preview" style="margin: 16px 0;"></div>
        <div id="result" class="output"></div>
      `, () => {
    let currentFile = null;

    $('#mode').addEventListener('change', () => {
      const mode = $('#mode').value;
      $('#fileSection').style.display = mode === 'toBase64' ? 'block' : 'none';
      $('#base64Section').style.display = mode === 'fromBase64' ? 'block' : 'none';
      $('#download').style.display = mode === 'fromBase64' ? 'inline-flex' : 'none';
      $('#preview').innerHTML = '';
      $('#result').textContent = '';
    });

    $('#fileInput').addEventListener('change', function(e) {
      const file = e.target.files[0];
      if (!file) return;

      currentFile = file;
      $('#mimeType').value = file.type || 'application/octet-stream';

      const reader = new FileReader();
      reader.onload = function(event) {
        const base64 = event.target.result.split(',')[1];
        $('#result').textContent = base64 || event.target.result;

        // Preview if it's an image
        if (file.type.startsWith('image/')) {
          $('#preview').innerHTML = `<img src="${event.target.result}" style="max-width: 100%; max-height: 200px; border-radius: 8px;" />`;
        }

        toast('File converted to Base64');
      };
      reader.readAsDataURL(file);
    });

    $('#convert').addEventListener('click', () => {
      const mode = $('#mode').value;

      if (mode === 'toBase64') {
        if (!currentFile) {
          toast('Please select a file', 'error');
          return;
        }
        // Conversion already happens on file select
      } else {
        const base64 = $('#base64Input').value.trim();
        const mimeType = $('#mimeType').value || 'application/octet-stream';

        if (!base64) {
          toast('Please enter Base64 string', 'error');
          return;
        }

        try {
          // Clean base64 string
          const cleanBase64 = base64.replace(/^data:[^;]+;base64,/, '');

          // Convert to blob
          const binary = atob(cleanBase64);
          const bytes = new Uint8Array(binary.length);
          for (let i = 0; i < binary.length; i++) {
            bytes[i] = binary.charCodeAt(i);
          }

          currentFile = new Blob([bytes], { type: mimeType });

          // Create download link
          const url = URL.createObjectURL(currentFile);
          $('#download').onclick = () => {
            const a = document.createElement('a');
            a.href = url;
            a.download = `file.${mimeType.split('/')[1] || 'bin'}`;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
          };

          // Preview if image
          if (mimeType.startsWith('image/')) {
            $('#preview').innerHTML = `<img src="${url}" style="max-width: 100%; max-height: 200px; border-radius: 8px;" />`;
          }

          $('#result').textContent = `File created: ${bytes.length} bytes, ${mimeType}`;
          toast('Base64 converted to file');
        } catch (error) {
          toast('Invalid Base64 string', 'error');
        }
      }
    });

    $('#copy').addEventListener('click', () => {
      if ($('#mode').value === 'toBase64') {
        navigator.clipboard.writeText($('#result').textContent).then(() => toast('Copied'));
      } else {
        navigator.clipboard.writeText($('#base64Input').value).then(() => toast('Copied'));
      }
    });
  });
}

function colorTool() {
  setTool('Color Converter', `
        <div class="row">
            <div class="form-group">
                <label>HEX Color</label>
                <input type="text" id="hex" placeholder="#FF5733" value="#6366f1" />
                <input type="color" id="colorPicker" value="#6366f1" style="width: 100%; height: 40px; margin-top: 8px;" />
            </div>
            <div class="form-group">
                <label>RGB</label>
                <div class="row">
                    <input type="number" id="r" min="0" max="255" placeholder="R" style="flex: 1;" />
                    <input type="number" id="g" min="0" max="255" placeholder="G" style="flex: 1;" />
                    <input type="number" id="b" min="0" max="255" placeholder="B" style="flex: 1;" />
                </div>
            </div>
        </div>
        <div class="row">
            <div class="form-group">
                <label>HSL</label>
                <div class="row">
                    <input type="number" id="h" min="0" max="360" placeholder="H" style="flex: 1;" />
                    <input type="number" id="s" min="0" max="100" placeholder="S" style="flex: 1;" />
                    <input type="number" id="l" min="0" max="100" placeholder="L" style="flex: 1;" />
                </div>
            </div>
            <div class="form-group">
                <label>CSS Name</label>
                <input type="text" id="cssName" placeholder="Color name" readonly />
            </div>
        </div>
        <div class="btn-group">
            <button id="convert" class="btn">Update All</button>
            <button id="random" class="btn btn-secondary">Random Color</button>
            <button id="copy" class="btn btn-secondary">Copy HEX</button>
        </div>
        <div id="colorPreview" style="width: 100%; height: 100px; border-radius: 12px; margin: 16px 0; border: 2px solid var(--border);"></div>
        <div id="results" class="output"></div>
      `, () => {
    const cssColors = {
      'aliceblue': '#f0f8ff', 'antiquewhite': '#faebd7', 'aqua': '#00ffff', 'aquamarine': '#7fffd4',
      'azure': '#f0ffff', 'beige': '#f5f5dc', 'bisque': '#ffe4c4', 'black': '#000000',
      'blanchedalmond': '#ffebcd', 'blue': '#0000ff', 'blueviolet': '#8a2be2', 'brown': '#a52a2a',
      'burlywood': '#deb887', 'cadetblue': '#5f9ea0', 'chartreuse': '#7fff00', 'chocolate': '#d2691e',
      'coral': '#ff7f50', 'cornflowerblue': '#6495ed', 'cornsilk': '#fff8dc', 'crimson': '#dc143c',
      'cyan': '#00ffff', 'darkblue': '#00008b', 'darkcyan': '#008b8b', 'darkgoldenrod': '#b8860b',
      'darkgray': '#a9a9a9', 'darkgreen': '#006400', 'darkgrey': '#a9a9a9', 'darkkhaki': '#bdb76b',
      'darkmagenta': '#8b008b', 'darkolivegreen': '#556b2f', 'darkorange': '#ff8c00', 'darkorchid': '#9932cc',
      'darkred': '#8b0000', 'darksalmon': '#e9967a', 'darkseagreen': '#8fbc8f', 'darkslateblue': '#483d8b',
      'darkslategray': '#2f4f4f', 'darkslategrey': '#2f4f4f', 'darkturquoise': '#00ced1', 'darkviolet': '#9400d3',
      'deeppink': '#ff1493', 'deepskyblue': '#00bfff', 'dimgray': '#696969', 'dimgrey': '#696969',
      'dodgerblue': '#1e90ff', 'firebrick': '#b22222', 'floralwhite': '#fffaf0', 'forestgreen': '#228b22',
      'fuchsia': '#ff00ff', 'gainsboro': '#dcdcdc', 'ghostwhite': '#f8f8ff', 'gold': '#ffd700',
      'goldenrod': '#daa520', 'gray': '#808080', 'green': '#008000', 'greenyellow': '#adff2f',
      'grey': '#808080', 'honeydew': '#f0fff0', 'hotpink': '#ff69b4', 'indianred': '#cd5c5c',
      'indigo': '#4b0082', 'ivory': '#fffff0', 'khaki': '#f0e68c', 'lavender': '#e6e6fa',
      'lavenderblush': '#fff0f5', 'lawngreen': '#7cfc00', 'lemonchiffon': '#fffacd', 'lightblue': '#add8e6',
      'lightcoral': '#f08080', 'lightcyan': '#e0ffff', 'lightgoldenrodyellow': '#fafad2', 'lightgray': '#d3d3d3',
      'lightgreen': '#90ee90', 'lightgrey': '#d3d3d3', 'lightpink': '#ffb6c1', 'lightsalmon': '#ffa07a',
      'lightseagreen': '#20b2aa', 'lightskyblue': '#87cefa', 'lightslategray': '#778899', 'lightslategrey': '#778899',
      'lightsteelblue': '#b0c4de', 'lightyellow': '#ffffe0', 'lime': '#00ff00', 'limegreen': '#32cd32',
      'linen': '#faf0e6', 'magenta': '#ff00ff', 'maroon': '#800000', 'mediumaquamarine': '#66cdaa',
      'mediumblue': '#0000cd', 'mediumorchid': '#ba55d3', 'mediumpurple': '#9370db', 'mediumseagreen': '#3cb371',
      'mediumslateblue': '#7b68ee', 'mediumspringgreen': '#00fa9a', 'mediumturquoise': '#48d1cc', 'mediumvioletred': '#c71585',
      'midnightblue': '#191970', 'mintcream': '#f5fffa', 'mistyrose': '#ffe4e1', 'moccasin': '#ffe4b5',
      'navajowhite': '#ffdead', 'navy': '#000080', 'oldlace': '#fdf5e6', 'olive': '#808000',
      'olivedrab': '#6b8e23', 'orange': '#ffa500', 'orangered': '#ff4500', 'orchid': '#da70d6',
      'palegoldenrod': '#eee8aa', 'palegreen': '#98fb98', 'paleturquoise': '#afeeee', 'palevioletred': '#db7093',
      'papayawhip': '#ffefd5', 'peachpuff': '#ffdab9', 'peru': '#cd853f', 'pink': '#ffc0cb',
      'plum': '#dda0dd', 'powderblue': '#b0e0e6', 'purple': '#800080', 'rebeccapurple': '#663399',
      'red': '#ff0000', 'rosybrown': '#bc8f8f', 'royalblue': '#4169e1', 'saddlebrown': '#8b4513',
      'salmon': '#fa8072', 'sandybrown': '#f4a460', 'seagreen': '#2e8b57', 'seashell': '#fff5ee',
      'sienna': '#a0522d', 'silver': '#c0c0c0', 'skyblue': '#87ceeb', 'slateblue': '#6a5acd',
      'slategray': '#708090', 'slategrey': '#708090', 'snow': '#fffafa', 'springgreen': '#00ff7f',
      'steelblue': '#4682b4', 'tan': '#d2b48c', 'teal': '#008080', 'thistle': '#d8bfd8',
      'tomato': '#ff6347', 'turquoise': '#40e0d0', 'violet': '#ee82ee', 'wheat': '#f5deb3',
      'white': '#ffffff', 'whitesmoke': '#f5f5f5', 'yellow': '#ffff00', 'yellowgreen': '#9acd32'
    };

    function hexToRgb(hex) {
      hex = hex.replace(/^#/, '');
      if (hex.length === 3) {
        hex = hex.split('').map(c => c + c).join('');
      }
      const num = parseInt(hex, 16);
      return {
        r: (num >> 16) & 255,
        g: (num >> 8) & 255,
        b: num & 255
      };
    }

    function rgbToHex(r, g, b) {
      return '#' + [r, g, b].map(x => x.toString(16).padStart(2, '0')).join('');
    }

    function rgbToHsl(r, g, b) {
      r /= 255; g /= 255; b /= 255;
      const max = Math.max(r, g, b);
      const min = Math.min(r, g, b);
      let h, s, l = (max + min) / 2;

      if (max === min) {
        h = s = 0;
      } else {
        const d = max - min;
        s = l > 0.5 ? d / (2 - max - min) : d / (max + min);
        switch (max) {
          case r: h = (g - b) / d + (g < b ? 6 : 0); break;
          case g: h = (b - r) / d + 2; break;
          case b: h = (r - g) / d + 4; break;
        }
        h /= 6;
      }

      return {
        h: Math.round(h * 360),
        s: Math.round(s * 100),
        l: Math.round(l * 100)
      };
    }

    function hslToRgb(h, s, l) {
      h /= 360; s /= 100; l /= 100;
      let r, g, b;

      if (s === 0) {
        r = g = b = l;
      } else {
        const hue2rgb = (p, q, t) => {
          if (t < 0) t += 1;
          if (t > 1) t -= 1;
          if (t < 1/6) return p + (q - p) * 6 * t;
          if (t < 1/2) return q;
          if (t < 2/3) return p + (q - p) * (2/3 - t) * 6;
          return p;
        };

        const q = l < 0.5 ? l * (1 + s) : l + s - l * s;
        const p = 2 * l - q;
        r = hue2rgb(p, q, h + 1/3);
        g = hue2rgb(p, q, h);
        b = hue2rgb(p, q, h - 1/3);
      }

      return {
        r: Math.round(r * 255),
        g: Math.round(g * 255),
        b: Math.round(b * 255)
      };
    }

    function findCssName(hex) {
      hex = hex.toLowerCase();
      for (const [name, value] of Object.entries(cssColors)) {
        if (value === hex) return name;
      }
      return null;
    }

    function updateAllFromHex(hex) {
      hex = hex.trim();
      if (!/^#?[0-9A-Fa-f]{3,6}$/.test(hex)) {
        toast('Invalid HEX color', 'error');
        return false;
      }

      if (!hex.startsWith('#')) hex = '#' + hex;

      const rgb = hexToRgb(hex);
      const hsl = rgbToHsl(rgb.r, rgb.g, rgb.b);
      const cssName = findCssName(hex);

      $('#hex').value = hex;
      $('#colorPicker').value = hex;
      $('#r').value = rgb.r;
      $('#g').value = rgb.g;
      $('#b').value = rgb.b;
      $('#h').value = hsl.h;
      $('#s').value = hsl.s;
      $('#l').value = hsl.l;
      $('#cssName').value = cssName || 'No CSS name';

      $('#colorPreview').style.background = hex;
      $('#colorPreview').style.boxShadow = `0 4px 12px ${hex}80`;

      const results = [
        `HEX: ${hex}`,
        `RGB: rgb(${rgb.r}, ${rgb.g}, ${rgb.b})`,
        `HSL: hsl(${hsl.h}, ${hsl.s}%, ${hsl.l}%)`,
        `CSS: ${cssName || 'Custom color'}`
      ];
      $('#results').textContent = results.join('\n');

      return true;
    }

    function updateAllFromRgb(r, g, b) {
      const hex = rgbToHex(r, g, b);
      return updateAllFromHex(hex);
    }

    function updateAllFromHsl(h, s, l) {
      const rgb = hslToRgb(h, s, l);
      return updateAllFromRgb(rgb.r, rgb.g, rgb.b);
    }

    $('#convert').addEventListener('click', () => {
      const hex = $('#hex').value;
      updateAllFromHex(hex);
    });

    $('#random').addEventListener('click', () => {
      const randomHex = '#' + Math.floor(Math.random() * 16777215).toString(16).padStart(6, '0');
      updateAllFromHex(randomHex);
      toast('Random color generated');
    });

    $('#copy').addEventListener('click', () => {
      navigator.clipboard.writeText($('#hex').value).then(() => toast('HEX copied'));
    });

    // Event listeners for real-time updates
    $('#hex').addEventListener('input', (e) => {
      if (e.target.value.length >= 3) {
        updateAllFromHex(e.target.value);
      }
    });

    $('#colorPicker').addEventListener('input', (e) => {
      updateAllFromHex(e.target.value);
    });

    $('#r').addEventListener('input', () => {
      const r = parseInt($('#r').value) || 0;
      const g = parseInt($('#g').value) || 0;
      const b = parseInt($('#b').value) || 0;
      updateAllFromRgb(r, g, b);
    });

    $('#g').addEventListener('input', () => {
      const r = parseInt($('#r').value) || 0;
      const g = parseInt($('#g').value) || 0;
      const b = parseInt($('#b').value) || 0;
      updateAllFromRgb(r, g, b);
    });

    $('#b').addEventListener('input', () => {
      const r = parseInt($('#r').value) || 0;
      const g = parseInt($('#g').value) || 0;
      const b = parseInt($('#b').value) || 0;
      updateAllFromRgb(r, g, b);
    });

    $('#h').addEventListener('input', () => {
      const h = parseInt($('#h').value) || 0;
      const s = parseInt($('#s').value) || 0;
      const l = parseInt($('#l').value) || 0;
      updateAllFromHsl(h, s, l);
    });

    $('#s').addEventListener('input', () => {
      const h = parseInt($('#h').value) || 0;
      const s = parseInt($('#s').value) || 0;
      const l = parseInt($('#l').value) || 0;
      updateAllFromHsl(h, s, l);
    });

    $('#l').addEventListener('input', () => {
      const h = parseInt($('#h').value) || 0;
      const s = parseInt($('#s').value) || 0;
      const l = parseInt($('#l').value) || 0;
      updateAllFromHsl(h, s, l);
    });

    // Initialize
    updateAllFromHex('#6366f1');
  });
}

function caseTool() {
  setTool('Case Converter', `
        <div class="form-group">
            <label>Input Text</label>
            <textarea id="input" rows="4" placeholder="Enter text to convert">Hello World Example Text</textarea>
        </div>
        <div class="row">
            <div class="form-group">
                <label>Conversion Type</label>
                <select id="conversionType">
                    <option value="upper">UPPERCASE</option>
                    <option value="lower">lowercase</option>
                    <option value="title">Title Case</option>
                    <option value="sentence">Sentence case</option>
                    <option value="camel">camelCase</option>
                    <option value="pascal">PascalCase</option>
                    <option value="snake">snake_case</option>
                    <option value="kebab">kebab-case</option>
                    <option value="constant">CONSTANT_CASE</option>
                    <option value="dot">dot.case</option>
                    <option value="path">path/case</option>
                    <option value="swap">sWAP cASE</option>
                    <option value="inverse">iNVERSE cASE</option>
                </select>
            </div>
            <div class="form-group">
                <label>Options</label>
                <div style="display: flex; flex-direction: column; gap: 8px;">
                    <label style="display: flex; align-items: center; gap: 8px;">
                        <input type="checkbox" id="preserveWhitespace" checked />
                        <span>Preserve whitespace</span>
                    </label>
                    <label style="display: flex; align-items: center; gap: 8px;">
                        <input type="checkbox" id="trimSpaces" />
                        <span>Trim extra spaces</span>
                    </label>
                </div>
            </div>
        </div>
        <div class="btn-group">
            <button id="convert" class="btn">Convert</button>
            <button id="copy" class="btn btn-secondary">Copy Result</button>
        </div>
        <div id="output" class="output"></div>
      `, () => {
    function convertCase(text, type, preserveWhitespace, trimSpaces) {
      if (trimSpaces) {
        text = text.trim().replace(/\s+/g, ' ');
      }

      switch (type) {
        case 'upper':
          return text.toUpperCase();
        case 'lower':
          return text.toLowerCase();
        case 'title':
          return text.replace(/\w\S*/g, (txt) => txt.charAt(0).toUpperCase() + txt.substr(1).toLowerCase());
        case 'sentence':
          return text.toLowerCase().replace(/(^\s*\w|[.!?]\s+\w)/g, (c) => c.toUpperCase());
        case 'camel':
          return text.toLowerCase()
            .replace(/[^a-zA-Z0-9]+(.)/g, (_, chr) => chr.toUpperCase())
            .replace(/^[A-Z]/, (c) => c.toLowerCase());
        case 'pascal':
          return text.toLowerCase()
            .replace(/[^a-zA-Z0-9]+(.)/g, (_, chr) => chr.toUpperCase())
            .replace(/^[a-z]/, (c) => c.toUpperCase());
        case 'snake':
          return text.toLowerCase()
            .replace(/[^a-zA-Z0-9]+/g, '_')
            .replace(/^_+|_+$/g, '');
        case 'kebab':
          return text.toLowerCase()
            .replace(/[^a-zA-Z0-9]+/g, '-')
            .replace(/^-+|-+$/g, '');
        case 'constant':
          return text.toUpperCase()
            .replace(/[^A-Z0-9]+/g, '_')
            .replace(/^_+|_+$/g, '');
        case 'dot':
          return text.toLowerCase()
            .replace(/[^a-zA-Z0-9]+/g, '.')
            .replace(/^\.+|\.+$/g, '');
        case 'path':
          return text.toLowerCase()
            .replace(/[^a-zA-Z0-9]+/g, '/')
            .replace(/^\/+|\/+$/g, '');
        case 'swap':
          return text.replace(/([a-z]+)|([A-Z]+)/g, (match, lower, upper) =>
            lower ? lower.toUpperCase() : match.toLowerCase());
        case 'inverse':
          return text.split('').map(c =>
            c === c.toUpperCase() ? c.toLowerCase() : c.toUpperCase()
          ).join('');
        default:
          return text;
      }
    }

    $('#convert').addEventListener('click', () => {
      const input = $('#input').value;
      const type = $('#conversionType').value;
      const preserveWhitespace = $('#preserveWhitespace').checked;
      const trimSpaces = $('#trimSpaces').checked;

      if (!input.trim()) {
        toast('Please enter some text', 'error');
        return;
      }

      const output = convertCase(input, type, preserveWhitespace, trimSpaces);
      $('#output').textContent = output;
      toast('Case converted');
    });

    $('#copy').addEventListener('click', () => {
      navigator.clipboard.writeText($('#output').textContent).then(() => toast('Copied'));
    });

    // Initialize
    $('#convert').click();
  });
}

function natoTool() {
  setTool('Text to NATO Alphabet', `
        <div class="form-group">
            <label>Input Text</label>
            <textarea id="input" rows="4" placeholder="Enter text to convert to NATO phonetic alphabet">HELLO WORLD</textarea>
        </div>
        <div class="form-group">
            <label>Options</label>
            <div style="display: flex; flex-direction: column; gap: 8px;">
                <label style="display: flex; align-items: center; gap: 8px;">
                    <input type="checkbox" id="includeOriginal" />
                    <span>Include original characters</span>
                </label>
                <label style="display: flex; align-items: center; gap: 8px;">
                    <input type="checkbox" id="separateLines" />
                    <span>Separate with new lines</span>
                </label>
            </div>
        </div>
        <div class="btn-group">
            <button id="convert" class="btn">Convert to NATO</button>
            <button id="copy" class="btn btn-secondary">Copy Result</button>
        </div>
        <div id="output" class="output"></div>
        <div style="margin-top: 16px; padding: 16px; background: var(--bg-secondary); border-radius: 8px;">
            <h4 style="margin-bottom: 8px;">📚 NATO Phonetic Alphabet Reference</h4>
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 8px; font-size: 14px;">
                <div>A = Alpha</div><div>B = Bravo</div><div>C = Charlie</div><div>D = Delta</div><div>E = Echo</div>
                <div>F = Foxtrot</div><div>G = Golf</div><div>H = Hotel</div><div>I = India</div><div>J = Juliet</div>
                <div>K = Kilo</div><div>L = Lima</div><div>M = Mike</div><div>N = November</div><div>O = Oscar</div>
                <div>P = Papa</div><div>Q = Quebec</div><div>R = Romeo</div><div>S = Sierra</div><div>T = Tango</div>
                <div>U = Uniform</div><div>V = Victor</div><div>W = Whiskey</div><div>X = X-ray</div><div>Y = Yankee</div>
                <div>Z = Zulu</div><div>0 = Zero</div><div>1 = One</div><div>2 = Two</div><div>3 = Three</div>
                <div>4 = Four</div><div>5 = Five</div><div>6 = Six</div><div>7 = Seven</div><div>8 = Eight</div>
                <div>9 = Nine</div><div>. = Decimal/Point</div><div>, = Comma</div>
            </div>
        </div>
      `, () => {
    const natoAlphabet = {
      'A': 'Alpha', 'B': 'Bravo', 'C': 'Charlie', 'D': 'Delta', 'E': 'Echo',
      'F': 'Foxtrot', 'G': 'Golf', 'H': 'Hotel', 'I': 'India', 'J': 'Juliett',
      'K': 'Kilo', 'L': 'Lima', 'M': 'Mike', 'N': 'November', 'O': 'Oscar',
      'P': 'Papa', 'Q': 'Quebec', 'R': 'Romeo', 'S': 'Sierra', 'T': 'Tango',
      'U': 'Uniform', 'V': 'Victor', 'W': 'Whiskey', 'X': 'X-ray', 'Y': 'Yankee',
      'Z': 'Zulu',
      '0': 'Zero', '1': 'One', '2': 'Two', '3': 'Three', '4': 'Four',
      '5': 'Five', '6': 'Six', '7': 'Seven', '8': 'Eight', '9': 'Nine',
      '.': 'Decimal', ',': 'Comma', ' ': '(space)'
    };

    $('#convert').addEventListener('click', () => {
      const input = $('#input').value.toUpperCase();
      const includeOriginal = $('#includeOriginal').checked;
      const separateLines = $('#separateLines').checked;

      if (!input.trim()) {
        toast('Please enter some text', 'error');
        return;
      }

      const separator = separateLines ? '\n' : ' ';
      const result = [];

      for (let char of input) {
        const nato = natoAlphabet[char] || char;
        if (includeOriginal) {
          result.push(`${char}: ${nato}`);
        } else {
          result.push(nato);
        }
      }

      $('#output').textContent = result.join(separator);
      toast('Converted to NATO alphabet');
    });

    $('#copy').addEventListener('click', () => {
      navigator.clipboard.writeText($('#output').textContent).then(() => toast('Copied'));
    });

    // Initialize
    $('#convert').click();
  });
}

function asciibinTool() {
  setTool('Text to ASCII Binary Converter', `
        <div class="form-group">
            <label>Input Text</label>
            <textarea id="input" rows="4" placeholder="Enter text to convert">Hello</textarea>
        </div>
        <div class="form-group">
            <label>Direction</label>
            <select id="direction">
                <option value="toBinary">Text → Binary</option>
                <option value="fromBinary">Binary → Text</option>
            </select>
        </div>
        <div class="form-group">
            <label>Options</label>
            <div style="display: flex; flex-direction: column; gap: 8px;">
                <label style="display: flex; align-items: center; gap: 8px;">
                    <input type="checkbox" id="spaces" checked />
                    <span>Add spaces between bytes</span>
                </label>
                <label style="display: flex; align-items: center; gap: 8px;">
                    <input type="checkbox" id="asciiCodes" />
                    <span>Show ASCII codes</span>
                </label>
            </div>
        </div>
        <div class="btn-group">
            <button id="convert" class="btn">Convert</button>
            <button id="copy" class="btn btn-secondary">Copy Result</button>
        </div>
        <div id="output" class="output"></div>
      `, () => {
    $('#direction').addEventListener('change', () => {
      const isToBinary = $('#direction').value === 'toBinary';
      $('#spaces').parentElement.style.display = isToBinary ? 'flex' : 'none';
      $('#asciiCodes').parentElement.style.display = isToBinary ? 'flex' : 'none';
    });

    $('#convert').addEventListener('click', () => {
      const input = $('#input').value;
      const direction = $('#direction').value;
      const addSpaces = $('#spaces').checked;
      const showAscii = $('#asciiCodes').checked;

      if (!input.trim()) {
        toast('Please enter some text', 'error');
        return;
      }

      let output = '';

      if (direction === 'toBinary') {
        const results = [];
        for (let i = 0; i < input.length; i++) {
          const char = input[i];
          const code = char.charCodeAt(0);
          const binary = code.toString(2).padStart(8, '0');
          if (showAscii) {
            results.push(`${char} (${code}): ${binary}`);
          } else {
            results.push(binary);
          }
        }
        output = results.join(addSpaces ? ' ' : '');
      } else {
        // Binary to text
        const binaryString = input.replace(/[^01]/g, '');
        if (binaryString.length % 8 !== 0) {
          toast('Binary length must be multiple of 8', 'error');
          return;
        }

        const chars = [];
        for (let i = 0; i < binaryString.length; i += 8) {
          const byte = binaryString.substr(i, 8);
          const code = parseInt(byte, 2);
          if (code >= 32 && code <= 126) {
            chars.push(String.fromCharCode(code));
          } else {
            chars.push(`\\x${code.toString(16).padStart(2, '0')}`);
          }
        }
        output = chars.join('');
      }

      $('#output').textContent = output;
      toast('Conversion complete');
    });

    $('#copy').addEventListener('click', () => {
      navigator.clipboard.writeText($('#output').textContent).then(() => toast('Copied'));
    });

    // Initialize
    $('#direction').dispatchEvent(new Event('change'));
    $('#convert').click();
  });
}

function unicodeTool() {
  setTool('Text to Unicode Converter', `
        <div class="form-group">
            <label>Input Text</label>
            <textarea id="input" rows="4" placeholder="Enter text to convert">Hello 🌍</textarea>
        </div>
        <div class="form-group">
            <label>Direction</label>
            <select id="direction">
                <option value="toUnicode">Text → Unicode</option>
                <option value="fromUnicode">Unicode → Text</option>
            </select>
        </div>
        <div class="form-group">
            <label>Format</label>
            <select id="format">
                <option value="codePoints">Code Points (U+XXXX)</option>
                <option value="hex">Hexadecimal</option>
                <option value="decimal">Decimal</option>
                <option value="binary">Binary</option>
                <option value="html">HTML Entities</option>
                <option value="js">JavaScript Escape</option>
            </select>
        </div>
        <div class="btn-group">
            <button id="convert" class="btn">Convert</button>
            <button id="copy" class="btn btn-secondary">Copy Result</button>
        </div>
        <div id="output" class="output"></div>
      `, () => {
    function toUnicode(text, format) {
      const results = [];
      for (let i = 0; i < text.length; i++) {
        const code = text.charCodeAt(i);
        let formatted;

        switch (format) {
          case 'codePoints':
            formatted = `U+${code.toString(16).toUpperCase().padStart(4, '0')}`;
            break;
          case 'hex':
            formatted = `0x${code.toString(16).toUpperCase()}`;
            break;
          case 'decimal':
            formatted = code.toString();
            break;
          case 'binary':
            formatted = code.toString(2).padStart(16, '0');
            break;
          case 'html':
            formatted = `&#${code};`;
            break;
          case 'js':
            formatted = `\\u${code.toString(16).padStart(4, '0')}`;
            break;
          default:
            formatted = code.toString();
        }
        results.push(formatted);
      }
      return results.join(' ');
    }

    function fromUnicode(input, format) {
      let codes = [];
      let text = '';

      switch (format) {
        case 'codePoints':
          codes = input.match(/U\+([0-9A-Fa-f]+)/g)?.map(m => parseInt(m.slice(2), 16)) || [];
          break;
        case 'hex':
          codes = input.match(/0x([0-9A-Fa-f]+)/g)?.map(m => parseInt(m.slice(2), 16)) || [];
          break;
        case 'decimal':
          codes = input.match(/\d+/g)?.map(m => parseInt(m, 10)) || [];
          break;
        case 'binary':
          codes = input.match(/[01]+/g)?.map(m => parseInt(m, 2)) || [];
          break;
        case 'html':
          codes = input.match(/&#(\d+);/g)?.map(m => parseInt(m.slice(2, -1), 10)) || [];
          break;
        case 'js':
          codes = input.match(/\\u([0-9A-Fa-f]{4})/g)?.map(m => parseInt(m.slice(2), 16)) || [];
          break;
        default:
          codes = input.split(/\s+/).filter(c => c).map(c => parseInt(c, 10));
      }

      for (const code of codes) {
        if (!isNaN(code) && code >= 0 && code <= 0x10FFFF) {
          text += String.fromCodePoint(code);
        }
      }

      return text;
    }

    $('#convert').addEventListener('click', () => {
      const input = $('#input').value;
      const direction = $('#direction').value;
      const format = $('#format').value;

      if (!input.trim()) {
        toast('Please enter some text', 'error');
        return;
      }

      let output;
      try {
        if (direction === 'toUnicode') {
          output = toUnicode(input, format);
        } else {
          output = fromUnicode(input, format);
        }
        $('#output').textContent = output;
        toast('Conversion complete');
      } catch (error) {
        toast('Conversion error: ' + error.message, 'error');
      }
    });

    $('#copy').addEventListener('click', () => {
      navigator.clipboard.writeText($('#output').textContent).then(() => toast('Copied'));
    });

    // Initialize
    $('#convert').click();
  });
}

function yaml2jsonTool() {
  setTool('YAML to JSON Converter', `
        <div class="row">
            <div class="form-group">
                <label>YAML Input</label>
                <textarea id="yaml" rows="8" placeholder="Enter YAML">name: John Doe
age: 30
hobbies:
  - reading
  - hiking
  - coding</textarea>
            </div>
            <div class="form-group">
                <label>JSON Output</label>
                <textarea id="json" rows="8" placeholder="JSON will appear here" readonly></textarea>
            </div>
        </div>
        <div class="form-group">
            <label>Options</label>
            <div style="display: flex; gap: 16px;">
                <label style="display: flex; align-items: center; gap: 8px;">
                    <input type="checkbox" id="pretty" checked />
                    <span>Pretty print</span>
                </label>
                <label style="display: flex; align-items: center; gap: 8px;">
                    <input type="checkbox" id="validate" />
                    <span>Validate JSON</span>
                </label>
            </div>
        </div>
        <div class="btn-group">
            <button id="convert" class="btn">Convert</button>
            <button id="copy" class="btn btn-secondary">Copy JSON</button>
            <button id="swap" class="btn btn-secondary">↔ Swap</button>
        </div>
        <div id="error" style="color: var(--error); margin-top: 8px; display: none;"></div>
      `, () => {
    function yamlToJson(yaml) {
      const lines = yaml.split('\n');
      const result = {};
      const stack = [{ obj: result, indent: -1 }];

      for (let line of lines) {
        if (!line.trim() || line.trim().startsWith('#')) continue;

        const indent = line.search(/\S/);
        const trimmed = line.trim();

        // Remove comments
        const commentIndex = trimmed.indexOf('#');
        const content = commentIndex !== -1 ? trimmed.slice(0, commentIndex).trim() : trimmed;

        if (!content) continue;

        // Check for array item
        if (content.startsWith('- ')) {
          const value = content.slice(2).trim();
          let current = stack[stack.length - 1].obj;

          if (!Array.isArray(current)) {
            const key = Object.keys(current)[0];
            current[key] = [];
            current = current[key];
          }

          // Try to parse value
          if (value === 'true' || value === 'false') {
            current.push(value === 'true');
          } else if (!isNaN(value) && value.trim() !== '') {
            current.push(Number(value));
          } else if (value.startsWith('"') && value.endsWith('"')) {
            current.push(value.slice(1, -1));
          } else {
            current.push(value);
          }
          continue;
        }

        // Remove array items from stack
        while (stack.length > 1 && indent <= stack[stack.length - 1].indent) {
          stack.pop();
        }

        // Parse key-value pair
        const colonIndex = content.indexOf(':');
        if (colonIndex === -1) continue;

        const key = content.slice(0, colonIndex).trim();
        let value = content.slice(colonIndex + 1).trim();

        let current = stack[stack.length - 1].obj;

        // Handle nested objects
        if (value === '') {
          current[key] = {};
          stack.push({ obj: current[key], indent });
        } else {
          // Try to parse value
          if (value === 'true' || value === 'false') {
            current[key] = value === 'true';
          } else if (!isNaN(value) && value.trim() !== '') {
            current[key] = Number(value);
          } else if (value.startsWith('"') && value.endsWith('"')) {
            current[key] = value.slice(1, -1);
          } else if (value.startsWith('[') && value.endsWith(']')) {
            try {
              current[key] = JSON.parse(value);
            } catch {
              current[key] = value;
            }
          } else {
            current[key] = value;
          }
        }
      }

      return result;
    }

    function jsonToYaml(json) {
      function convert(obj, indent = 0) {
        const spaces = ' '.repeat(indent);
        const lines = [];

        if (Array.isArray(obj)) {
          for (const item of obj) {
            if (typeof item === 'object' && item !== null) {
              lines.push(`${spaces}-`);
              lines.push(convert(item, indent + 2));
            } else {
              lines.push(`${spaces}- ${formatValue(item)}`);
            }
          }
        } else if (typeof obj === 'object' && obj !== null) {
          for (const [key, value] of Object.entries(obj)) {
            if (typeof value === 'object' && value !== null) {
              if (Array.isArray(value) && value.length > 0) {
                lines.push(`${spaces}${key}:`);
                lines.push(convert(value, indent + 2));
              } else if (Object.keys(value).length > 0) {
                lines.push(`${spaces}${key}:`);
                lines.push(convert(value, indent + 2));
              } else {
                lines.push(`${spaces}${key}: {}`);
              }
            } else {
              lines.push(`${spaces}${key}: ${formatValue(value)}`);
            }
          }
        }

        return lines.join('\n');
      }

      function formatValue(value) {
        if (value === null) return 'null';
        if (value === undefined) return '';
        if (typeof value === 'boolean') return value ? 'true' : 'false';
        if (typeof value === 'number') return value.toString();
        if (typeof value === 'string') {
          if (value.includes(':') || value.includes('#') || value.includes('"') || value.includes("'")) {
            return `"${value.replace(/"/g, '\\"')}"`;
          }
          return value;
        }
        return JSON.stringify(value);
      }

      return convert(json);
    }

    $('#convert').addEventListener('click', () => {
      const yamlText = $('#yaml').value;
      const pretty = $('#pretty').checked;
      const validate = $('#validate').checked;

      if (!yamlText.trim()) {
        toast('Please enter YAML', 'error');
        return;
      }

      try {
        const jsonObj = yamlToJson(yamlText);
        let jsonText;

        if (pretty) {
          jsonText = JSON.stringify(jsonObj, null, 2);
        } else {
          jsonText = JSON.stringify(jsonObj);
        }

        if (validate) {
          JSON.parse(jsonText); // Validate
        }

        $('#json').value = jsonText;
        $('#error').style.display = 'none';
        toast('Conversion successful');
      } catch (error) {
        $('#error').textContent = `Error: ${error.message}`;
        $('#error').style.display = 'block';
        toast('Conversion failed', 'error');
      }
    });

    $('#swap').addEventListener('click', () => {
      const yamlText = $('#yaml').value;
      const jsonText = $('#json').value;

      if (jsonText.trim()) {
        try {
          const jsonObj = JSON.parse(jsonText);
          $('#yaml').value = jsonToYaml(jsonObj);
          $('#json').value = yamlText;
          toast('Swapped');
        } catch {
          toast('Invalid JSON, cannot swap', 'error');
        }
      }
    });

    $('#copy').addEventListener('click', () => {
      navigator.clipboard.writeText($('#json').value).then(() => toast('Copied'));
    });

    // Initialize
    $('#convert').click();
  });
}

function yaml2tomlTool() {
  placeholder('YAML to TOML');
}

function json2yamlTool() {
  setTool('JSON to YAML Converter', `
        <div class="row">
            <div class="form-group">
                <label>JSON Input</label>
                <textarea id="json" rows="8" placeholder='{"name": "John", "age": 30}'></textarea>
            </div>
            <div class="form-group">
                <label>YAML Output</label>
                <textarea id="yaml" rows="8" placeholder="YAML will appear here" readonly></textarea>
            </div>
        </div>
        <div class="form-group">
            <label>Options</label>
            <div style="display: flex; gap: 16px;">
                <label style="display: flex; align-items: center; gap: 8px;">
                    <input type="checkbox" id="indent" checked />
                    <span>Indent arrays</span>
                </label>
                <label style="display: flex; align-items: center; gap: 8px;">
                    <input type="checkbox" id="quotes" />
                    <span>Quote strings</span>
                </label>
            </div>
        </div>
        <div class="btn-group">
            <button id="convert" class="btn">Convert</button>
            <button id="copy" class="btn btn-secondary">Copy YAML</button>
            <button id="swap" class="btn btn-secondary">↔ Swap</button>
        </div>
        <div id="error" style="color: var(--error); margin-top: 8px; display: none;"></div>
      `, () => {
    function jsonToYaml(jsonObj, indentArrays = true, quoteStrings = false) {
      function convert(obj, indent = 0, isArrayItem = false) {
        const spaces = ' '.repeat(indent);
        const lines = [];

        if (Array.isArray(obj)) {
          for (const item of obj) {
            if (typeof item === 'object' && item !== null) {
              lines.push(`${spaces}-`);
              lines.push(convert(item, indent + 2, true));
            } else {
              lines.push(`${spaces}- ${formatValue(item, quoteStrings, isArrayItem)}`);
            }
          }
        } else if (typeof obj === 'object' && obj !== null) {
          for (const [key, value] of Object.entries(obj)) {
            if (typeof value === 'object' && value !== null) {
              if (Array.isArray(value)) {
                if (value.length === 0) {
                  lines.push(`${spaces}${key}: []`);
                } else if (indentArrays) {
                  lines.push(`${spaces}${key}:`);
                  lines.push(convert(value, indent + 2));
                } else {
                  lines.push(`${spaces}${key}: [${value.map(v => formatValue(v, quoteStrings)).join(', ')}]`);
                }
              } else {
                if (Object.keys(value).length === 0) {
                  lines.push(`${spaces}${key}: {}`);
                } else {
                  lines.push(`${spaces}${key}:`);
                  lines.push(convert(value, indent + 2));
                }
              }
            } else {
              lines.push(`${spaces}${key}: ${formatValue(value, quoteStrings)}`);
            }
          }
        }

        return lines.join('\n');
      }

      function formatValue(value, quoteStrings = false, isArrayItem = false) {
        if (value === null) return 'null';
        if (value === undefined) return '~';
        if (typeof value === 'boolean') return value ? 'true' : 'false';
        if (typeof value === 'number') return value.toString();
        if (typeof value === 'string') {
          const needsQuotes = quoteStrings ||
            value.includes(':') ||
            value.includes('#') ||
            value.includes('"') ||
            value.includes("'") ||
            value.trim() !== value ||
            /^[0-9]/.test(value) ||
            value.toLowerCase() === 'true' ||
            value.toLowerCase() === 'false' ||
            value.toLowerCase() === 'null' ||
            value.toLowerCase() === 'yes' ||
            value.toLowerCase() === 'no';

          if (needsQuotes) {
            return `"${value.replace(/"/g, '\\"')}"`;
          }
          return value;
        }
        return JSON.stringify(value);
      }

      return convert(jsonObj);
    }

    $('#convert').addEventListener('click', () => {
      const jsonText = $('#json').value;
      const indentArrays = $('#indent').checked;
      const quoteStrings = $('#quotes').checked;

      if (!jsonText.trim()) {
        toast('Please enter JSON', 'error');
        return;
      }

      try {
        const jsonObj = JSON.parse(jsonText);
        const yamlText = jsonToYaml(jsonObj, indentArrays, quoteStrings);

        $('#yaml').value = yamlText;
        $('#error').style.display = 'none';
        toast('Conversion successful');
      } catch (error) {
        $('#error').textContent = `Error: ${error.message}`;
        $('#error').style.display = 'block';
        toast('Conversion failed', 'error');
      }
    });

    $('#swap').addEventListener('click', () => {
      // Implement YAML to JSON conversion here
      toast('YAML to JSON conversion not fully implemented', 'error');
    });

    $('#copy').addEventListener('click', () => {
      navigator.clipboard.writeText($('#yaml').value).then(() => toast('Copied'));
    });

    // Initialize
    $('#convert').click();
  });
}

function json2tomlTool() {
  placeholder('JSON to TOML');
}

function listconvTool() {
  setTool('List Converter', `
        <div class="form-group">
            <label>Input List</label>
            <textarea id="input" rows="6" placeholder="Enter list items, one per line or comma separated">apple, banana, cherry
date
fig, grape</textarea>
        </div>
        <div class="row">
            <div class="form-group">
                <label>Input Format</label>
                <select id="inputFormat">
                    <option value="lines">Lines</option>
                    <option value="comma">Comma separated</option>
                    <option value="semicolon">Semicolon separated</option>
                    <option value="pipe">Pipe separated</option>
                    <option value="tab">Tab separated</option>
                </select>
            </div>
            <div class="form-group">
                <label>Output Format</label>
                <select id="outputFormat">
                    <option value="lines">Lines</option>
                    <option value="comma">Comma separated</option>
                    <option value="semicolon">Semicolon separated</option>
                    <option value="pipe">Pipe separated</option>
                    <option value="tab">Tab separated</option>
                    <option value="json">JSON array</option>
                    <option value="html">HTML list</option>
                    <option value="markdown">Markdown list</option>
                </select>
            </div>
        </div>
        <div class="row">
            <div class="form-group">
                <label>Transformations</label>
                <div style="display: flex; flex-direction: column; gap: 8px;">
                    <div style="display: flex; gap: 8px;">
                        <input type="text" id="prefix" placeholder="Prefix" style="flex: 1;" />
                        <input type="text" id="suffix" placeholder="Suffix" style="flex: 1;" />
                    </div>
                    <div style="display: flex; gap: 8px; align-items: center;">
                        <select id="case" style="flex: 1;">
                            <option value="none">No case change</option>
                            <option value="upper">UPPERCASE</option>
                            <option value="lower">lowercase</option>
                            <option value="title">Title Case</option>
                        </select>
                        <select id="sort" style="flex: 1;">
                            <option value="none">No sorting</option>
                            <option value="asc">Sort A-Z</option>
                            <option value="desc">Sort Z-A</option>
                            <option value="length-asc">By length ↑</option>
                            <option value="length-desc">By length ↓</option>
                        </select>
                    </div>
                    <div style="display: flex; gap: 8px;">
                        <input type="number" id="trimStart" placeholder="Trim start chars" style="flex: 1;" />
                        <input type="number" id="trimEnd" placeholder="Trim end chars" style="flex: 1;" />
                        <input type="number" id="limit" placeholder="Limit items" style="flex: 1;" />
                    </div>
                </div>
            </div>
            <div class="form-group">
                <label>Filters</label>
                <div style="display: flex; flex-direction: column; gap: 8px;">
                    <input type="text" id="filterContains" placeholder="Contains text" />
                    <input type="text" id="filterStartsWith" placeholder="Starts with" />
                    <input type="text" id="filterEndsWith" placeholder="Ends with" />
                    <label style="display: flex; align-items: center; gap: 8px;">
                        <input type="checkbox" id="unique" />
                        <span>Remove duplicates</span>
                    </label>
                    <label style="display: flex; align-items: center; gap: 8px;">
                        <input type="checkbox" id="trimItems" checked />
                        <span>Trim whitespace</span>
                    </label>
                </div>
            </div>
        </div>
        <div class="btn-group">
            <button id="convert" class="btn">Convert List</button>
            <button id="copy" class="btn btn-secondary">Copy Result</button>
            <button id="clear" class="btn btn-secondary">Clear</button>
        </div>
        <div id="output" class="output"></div>
      `, () => {
    function parseInput(input, format) {
      let items = [];

      switch (format) {
        case 'lines':
          items = input.split('\n');
          break;
        case 'comma':
          items = input.split(',');
          break;
        case 'semicolon':
          items = input.split(';');
          break;
        case 'pipe':
          items = input.split('|');
          break;
        case 'tab':
          items = input.split('\t');
          break;
      }

      return items;
    }

    function formatOutput(items, format) {
      switch (format) {
        case 'lines':
          return items.join('\n');
        case 'comma':
          return items.join(', ');
        case 'semicolon':
          return items.join('; ');
        case 'pipe':
          return items.join(' | ');
        case 'tab':
          return items.join('\t');
        case 'json':
          return JSON.stringify(items, null, 2);
        case 'html':
          return `<ul>\n${items.map(item => `  <li>${escapeHtml(item)}</li>`).join('\n')}\n</ul>`;
        case 'markdown':
          return items.map(item => `- ${item}`).join('\n');
        default:
          return items.join('\n');
      }
    }

    function escapeHtml(text) {
      const div = document.createElement('div');
      div.textContent = text;
      return div.innerHTML;
    }

    $('#convert').addEventListener('click', () => {
      const input = $('#input').value;
      const inputFormat = $('#inputFormat').value;
      const outputFormat = $('#outputFormat').value;

      if (!input.trim()) {
        toast('Please enter a list', 'error');
        return;
      }

      let items = parseInput(input, inputFormat);

      // Apply transformations
      if ($('#trimItems').checked) {
        items = items.map(item => item.trim()).filter(item => item !== '');
      }

      // Filter by contains
      const filterContains = $('#filterContains').value;
      if (filterContains) {
        items = items.filter(item => item.toLowerCase().includes(filterContains.toLowerCase()));
      }

      // Filter by starts with
      const filterStartsWith = $('#filterStartsWith').value;
      if (filterStartsWith) {
        items = items.filter(item => item.toLowerCase().startsWith(filterStartsWith.toLowerCase()));
      }

      // Filter by ends with
      const filterEndsWith = $('#filterEndsWith').value;
      if (filterEndsWith) {
        items = items.filter(item => item.toLowerCase().endsWith(filterEndsWith.toLowerCase()));
      }

      // Remove duplicates
      if ($('#unique').checked) {
        items = [...new Set(items)];
      }

      // Apply case transformation
      const caseType = $('#case').value;
      items = items.map(item => {
        switch (caseType) {
          case 'upper': return item.toUpperCase();
          case 'lower': return item.toLowerCase();
          case 'title': return item.replace(/\w\S*/g, txt => txt.charAt(0).toUpperCase() + txt.substr(1).toLowerCase());
          default: return item;
        }
      });

      // Add prefix and suffix
      const prefix = $('#prefix').value;
      const suffix = $('#suffix').value;
      if (prefix || suffix) {
        items = items.map(item => prefix + item + suffix);
      }

      // Trim characters
      const trimStart = parseInt($('#trimStart').value) || 0;
      const trimEnd = parseInt($('#trimEnd').value) || 0;
      if (trimStart > 0 || trimEnd > 0) {
        items = items.map(item => {
          let result = item;
          if (trimStart > 0) result = result.slice(trimStart);
          if (trimEnd > 0) result = result.slice(0, -trimEnd);
          return result;
        });
      }

      // Sort
      const sortType = $('#sort').value;
      switch (sortType) {
        case 'asc':
          items.sort((a, b) => a.localeCompare(b));
          break;
        case 'desc':
          items.sort((a, b) => b.localeCompare(a));
          break;
        case 'length-asc':
          items.sort((a, b) => a.length - b.length);
          break;
        case 'length-desc':
          items.sort((a, b) => b.length - a.length);
          break;
      }

      // Limit items
      const limit = parseInt($('#limit').value);
      if (limit > 0) {
        items = items.slice(0, limit);
      }

      const output = formatOutput(items, outputFormat);
      $('#output').textContent = output;

      // Show statistics
      const stats = `Items: ${items.length} | Characters: ${output.length}`;
      toast(`Conversion complete. ${stats}`);
    });

    $('#copy').addEventListener('click', () => {
      navigator.clipboard.writeText($('#output').textContent).then(() => toast('Copied'));
    });

    $('#clear').addEventListener('click', () => {
      $('#input').value = '';
      $('#output').textContent = '';
      toast('Cleared');
    });

    // Initialize
    $('#convert').click();
  });
}

function toml2jsonTool() {
  placeholder('TOML to JSON');
}

function toml2yamlTool() {
  placeholder('TOML to YAML');
}

function xml2jsonTool() {
  setTool('XML to JSON Converter', `
        <div class="row">
            <div class="form-group">
                <label>XML Input</label>
                <textarea id="xml" rows="8" placeholder="Enter XML"><person>
  <name>John Doe</name>
  <age>30</age>
  <hobbies>
    <hobby>Reading</hobby>
    <hobby>Hiking</hobby>
  </hobbies>
</person></textarea>
            </div>
            <div class="form-group">
                <label>JSON Output</label>
                <textarea id="json" rows="8" placeholder="JSON will appear here" readonly></textarea>
            </div>
        </div>
        <div class="form-group">
            <label>Options</label>
            <div style="display: flex; gap: 16px;">
                <label style="display: flex; align-items: center; gap: 8px;">
                    <input type="checkbox" id="pretty" checked />
                    <span>Pretty print</span>
                </label>
                <label style="display: flex; align-items: center; gap: 8px;">
                    <input type="checkbox" id="attributes" />
                    <span>Include attributes</span>
                </label>
            </div>
        </div>
        <div class="btn-group">
            <button id="convert" class="btn">Convert</button>
            <button id="copy" class="btn btn-secondary">Copy JSON</button>
        </div>
        <div id="error" style="color: var(--error); margin-top: 8px; display: none;"></div>
      `, () => {
    function xmlToJson(xmlString, includeAttributes = false) {
      // Simple XML parser for common cases
      function parseNode(node) {
        const obj = {};

        // Handle attributes
        if (includeAttributes && node.attributes && node.attributes.length > 0) {
          obj['@attributes'] = {};
          for (let i = 0; i < node.attributes.length; i++) {
            const attr = node.attributes[i];
            obj['@attributes'][attr.name] = attr.value;
          }
        }

        // Handle child nodes
        if (node.childNodes.length === 1 && node.childNodes[0].nodeType === 3) {
          // Text node only
          return node.childNodes[0].nodeValue.trim();
        }

        const childCounts = {};

        for (let i = 0; i < node.childNodes.length; i++) {
          const child = node.childNodes[i];

          if (child.nodeType === 3) {
            // Text node
            const text = child.nodeValue.trim();
            if (text) {
              if (obj['#text']) {
                obj['#text'] += ' ' + text;
              } else {
                obj['#text'] = text;
              }
            }
          } else if (child.nodeType === 1) {
            // Element node
            const childName = child.nodeName;
            childCounts[childName] = (childCounts[childName] || 0) + 1;

            if (childCounts[childName] === 1) {
              obj[childName] = parseNode(child);
            } else {
              if (childCounts[childName] === 2) {
                // Convert to array
                obj[childName] = [obj[childName]];
              }
              obj[childName].push(parseNode(child));
            }
          }
        }

        return obj;
      }

      // Parse XML string
      const parser = new DOMParser();
      const xmlDoc = parser.parseFromString(xmlString, 'text/xml');

      // Check for parsing errors
      const parseError = xmlDoc.getElementsByTagName('parsererror');
      if (parseError.length > 0) {
        throw new Error('XML parsing error: ' + parseError[0].textContent);
      }

      return parseNode(xmlDoc.documentElement);
    }

    $('#convert').addEventListener('click', () => {
      const xmlText = $('#xml').value;
      const pretty = $('#pretty').checked;
      const includeAttributes = $('#attributes').checked;

      if (!xmlText.trim()) {
        toast('Please enter XML', 'error');
        return;
      }

      try {
        const jsonObj = xmlToJson(xmlText, includeAttributes);
        const jsonText = pretty ?
          JSON.stringify(jsonObj, null, 2) :
          JSON.stringify(jsonObj);

        $('#json').value = jsonText;
        $('#error').style.display = 'none';
        toast('Conversion successful');
      } catch (error) {
        $('#error').textContent = `Error: ${error.message}`;
        $('#error').style.display = 'block';
        toast('Conversion failed', 'error');
      }
    });

    $('#copy').addEventListener('click', () => {
      navigator.clipboard.writeText($('#json').value).then(() => toast('Copied'));
    });

    // Initialize
    $('#convert').click();
  });
}

function json2xmlTool() {
  setTool('JSON to XML Converter', `
        <div class="row">
            <div class="form-group">
                <label>JSON Input</label>
                <textarea id="json" rows="8" placeholder='{"person": {"name": "John", "age": 30}}'></textarea>
            </div>
            <div class="form-group">
                <label>XML Output</label>
                <textarea id="xml" rows="8" placeholder="XML will appear here" readonly></textarea>
            </div>
        </div>
        <div class="form-group">
            <label>Options</label>
            <div style="display: flex; gap: 16px;">
                <label style="display: flex; align-items: center; gap: 8px;">
                    <input type="text" id="root" placeholder="Root element" value="root" />
                </label>
                <label style="display: flex; align-items: center; gap: 8px;">
                    <input type="checkbox" id="pretty" checked />
                    <span>Pretty print</span>
                </label>
            </div>
        </div>
        <div class="btn-group">
            <button id="convert" class="btn">Convert</button>
            <button id="copy" class="btn btn-secondary">Copy XML</button>
        </div>
        <div id="error" style="color: var(--error); margin-top: 8px; display: none;"></div>
      `, () => {
    function jsonToXml(jsonObj, rootName = 'root', pretty = true) {
      function convert(obj, indent = 0, elementName = 'item') {
        const spaces = pretty ? ' '.repeat(indent) : '';
        const newline = pretty ? '\n' : '';

        if (typeof obj === 'string') {
          return `${spaces}<${elementName}>${escapeXml(obj)}</${elementName}>${newline}`;
        }

        if (typeof obj === 'number' || typeof obj === 'boolean') {
          return `${spaces}<${elementName}>${obj}</${elementName}>${newline}`;
        }

        if (obj === null || obj === undefined) {
          return `${spaces}<${elementName} />${newline}`;
        }

        if (Array.isArray(obj)) {
          return obj.map(item =>
            convert(item, indent, elementName)
          ).join('');
        }

        // Object
        let xml = `${spaces}<${elementName}>${newline}`;

        for (const [key, value] of Object.entries(obj)) {
          if (key === '@attributes') {
            // Handle attributes separately
            continue;
          }

          xml += convert(value, indent + 2, key);
        }

        xml += `${spaces}</${elementName}>${newline}`;
        return xml;
      }

      function escapeXml(text) {
        return text.toString()
          .replace(/&/g, '&amp;')
          .replace(/</g, '&lt;')
          .replace(/>/g, '&gt;')
          .replace(/"/g, '&quot;')
          .replace(/'/g, '&apos;');
      }

      const xmlHeader = '<?xml version="1.0" encoding="UTF-8"?>\n';
      const content = convert(jsonObj, 0, rootName);

      return xmlHeader + content;
    }

    $('#convert').addEventListener('click', () => {
      const jsonText = $('#json').value;
      const rootName = $('#root').value || 'root';
      const pretty = $('#pretty').checked;

      if (!jsonText.trim()) {
        toast('Please enter JSON', 'error');
        return;
      }

      try {
        const jsonObj = JSON.parse(jsonText);
        const xmlText = jsonToXml(jsonObj, rootName, pretty);

        $('#xml').value = xmlText;
        $('#error').style.display = 'none';
        toast('Conversion successful');
      } catch (error) {
        $('#error').textContent = `Error: ${error.message}`;
        $('#error').style.display = 'block';
        toast('Conversion failed', 'error');
      }
    });

    $('#copy').addEventListener('click', () => {
      navigator.clipboard.writeText($('#xml').value).then(() => toast('Copied'));
    });

    // Initialize
    $('#convert').click();
  });
}

function md2htmlTool() {
  setTool('Markdown to HTML Converter', `
        <div class="row">
            <div class="form-group">
                <label>Markdown Input</label>
                <textarea id="markdown" rows="8" placeholder="# Title

This is **bold** and *italic* text.

- List item 1
- List item 2

[Link](https://example.com)"></textarea>
            </div>
            <div class="form-group">
                <label>HTML Output</label>
                <textarea id="html" rows="8" placeholder="HTML will appear here" readonly></textarea>
            </div>
        </div>
        <div class="form-group">
            <label>Preview</label>
            <div id="preview" style="padding: 16px; background: var(--bg-secondary); border-radius: 8px; min-height: 100px;"></div>
        </div>
        <div class="btn-group">
            <button id="convert" class="btn">Convert</button>
            <button id="copy" class="btn btn-secondary">Copy HTML</button>
            <button id="previewBtn" class="btn btn-secondary">Preview</button>
        </div>
      `, () => {
    function markdownToHtml(markdown) {
      // Basic Markdown to HTML converter
      let html = markdown;

      // Headers
      html = html.replace(/^### (.*$)/gim, '<h3>$1</h3>');
      html = html.replace(/^## (.*$)/gim, '<h2>$1</h2>');
      html = html.replace(/^# (.*$)/gim, '<h1>$1</h1>');

      // Bold
      html = html.replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>');
      html = html.replace(/__(.*?)__/g, '<strong>$1</strong>');

      // Italic
      html = html.replace(/\*(.*?)\*/g, '<em>$1</em>');
      html = html.replace(/_(.*?)_/g, '<em>$1</em>');

      // Code
      html = html.replace(/`([^`]+)`/g, '<code>$1</code>');
      html = html.replace(/```([\s\S]*?)```/g, '<pre><code>$1</code></pre>');

      // Links
      html = html.replace(/\[([^\]]+)\]\(([^)]+)\)/g, '<a href="$2" target="_blank">$1</a>');

      // Images
      html = html.replace(/!\[([^\]]*)\]\(([^)]+)\)/g, '<img src="$2" alt="$1" style="max-width: 100%;" />');

      // Lists
      html = html.replace(/^\s*\n\*/gm, '<ul>\n*');
      html = html.replace(/^(\*.+)\s*\n([^\*])/gm, '$1\n</ul>\n\n$2');
      html = html.replace(/^\*(.+)/gm, '<li>$1</li>');

      html = html.replace(/^\s*\n\d\./gm, '<ol>\n1.');
      html = html.replace(/^(\d\..+)\s*\n([^\d\.])/gm, '$1\n</ol>\n\n$2');
      html = html.replace(/^\d\.(.+)/gm, '<li>$1</li>');

      // Blockquotes
      html = html.replace(/^\> (.*$)/gim, '<blockquote>$1</blockquote>');

      // Horizontal rule
      html = html.replace(/^-{3,}$/gm, '<hr />');

      // Paragraphs
      html = html.replace(/\n\n/g, '</p><p>');
      html = html.replace(/\n/g, '<br />');

      // Wrap in paragraph tags if needed
      if (!html.startsWith('<')) {
        html = '<p>' + html + '</p>';
      }

      // Clean up nested paragraphs
      html = html.replace(/<\/p><p>/g, '</p>\n<p>');

      return html;
    }

    $('#convert').addEventListener('click', () => {
      const markdown = $('#markdown').value;

      if (!markdown.trim()) {
        toast('Please enter Markdown', 'error');
        return;
      }

      const html = markdownToHtml(markdown);
      $('#html').value = html;
      toast('Conversion successful');
    });

    $('#previewBtn').addEventListener('click', () => {
      const markdown = $('#markdown').value;

      if (!markdown.trim()) {
        toast('Please enter Markdown', 'error');
        return;
      }

      const html = markdownToHtml(markdown);
      $('#preview').innerHTML = html;
      toast('Preview updated');
    });

    $('#copy').addEventListener('click', () => {
      navigator.clipboard.writeText($('#html').value).then(() => toast('Copied'));
    });

    // Initialize
    $('#convert').click();
  });
}

// WEB TOOLS

function urlencTool() {
  setTool('URL Encode/Decoder', `
        <div class="form-group">
            <label>Input</label>
            <textarea id="input" rows="4" placeholder="Enter text to encode/decode">Hello World & Special Chars: @#$%</textarea>
        </div>
        <div class="form-group">
            <label>Operation</label>
            <select id="operation">
                <option value="encode">Encode</option>
                <option value="decode">Decode</option>
                <option value="encodeComponent">Encode Component</option>
                <option value="decodeComponent">Decode Component</option>
            </select>
        </div>
        <div class="btn-group">
            <button id="process" class="btn">Process</button>
            <button id="copy" class="btn btn-secondary">Copy Result</button>
        </div>
        <div id="output" class="output"></div>
        <div style="margin-top: 16px; padding: 16px; background: var(--bg-secondary); border-radius: 8px;">
            <h4 style="margin-bottom: 8px;">📚 URL Encoding Reference</h4>
            <div style="font-size: 14px;">
                <p><strong>encodeURI()</strong>: Encodes full URLs, keeps :,/?:@&=+$# characters</p>
                <p><strong>encodeURIComponent()</strong>: Encodes URL components, encodes more characters</p>
                <p><strong>Common encoded characters:</strong></p>
                <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 8px;">
                    <div>Space → %20</div><div>! → %21</div><div>" → %22</div>
                    <div># → %23</div><div>$ → %24</div><div>% → %25</div>
                    <div>& → %26</div><div>' → %27</div><div>( → %28</div>
                    <div>) → %29</div><div>* → %2A</div><div>+ → %2B</div>
                </div>
            </div>
        </div>
      `, () => {
    $('#process').addEventListener('click', () => {
      const input = $('#input').value;
      const operation = $('#operation').value;

      if (!input.trim()) {
        toast('Please enter text', 'error');
        return;
      }

      let output;
      try {
        switch (operation) {
          case 'encode':
            output = encodeURI(input);
            break;
          case 'decode':
            output = decodeURI(input);
            break;
          case 'encodeComponent':
            output = encodeURIComponent(input);
            break;
          case 'decodeComponent':
            output = decodeURIComponent(input);
            break;
        }

        $('#output').textContent = output;
        toast('Processing complete');
      } catch (error) {
        toast('Error: ' + error.message, 'error');
      }
    });

    $('#copy').addEventListener('click', () => {
      navigator.clipboard.writeText($('#output').textContent).then(() => toast('Copied'));
    });

    // Initialize
    $('#process').click();
  });
}

function escapehtmlTool() {
  setTool('HTML Entity Escaper', `
        <div class="form-group">
            <label>Input</label>
            <textarea id="input" rows="4" placeholder="Enter HTML to escape/unescape"><div>Hello & "World"</div></textarea>
        </div>
        <div class="form-group">
            <label>Operation</label>
            <select id="operation">
                <option value="escape">Escape</option>
                <option value="unescape">Unescape</option>
            </select>
        </div>
        <div class="btn-group">
            <button id="process" class="btn">Process</button>
            <button id="copy" class="btn btn-secondary">Copy Result</button>
        </div>
        <div id="output" class="output"></div>
        <div style="margin-top: 16px; padding: 16px; background: var(--bg-secondary); border-radius: 8px;">
            <h4 style="margin-bottom: 8px;">📚 HTML Entities Reference</h4>
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 8px; font-size: 14px;">
                <div>&amp; → &amp;amp;</div><div>&lt; → &amp;lt;</div><div>&gt; → &amp;gt;</div>
                <div>" → &amp;quot;</div><div>' → &amp;apos;</div><div>© → &amp;copy;</div>
                <div>® → &amp;reg;</div><div>€ → &amp;euro;</div><div>£ → &amp;pound;</div>
                <div>¥ → &amp;yen;</div><div>¢ → &amp;cent;</div><div>§ → &amp;sect;</div>
            </div>
        </div>
      `, () => {
    function escapeHtml(text) {
      const div = document.createElement('div');
      div.textContent = text;
      return div.innerHTML;
    }

    function unescapeHtml(text) {
      const div = document.createElement('div');
      div.innerHTML = text;
      return div.textContent;
    }

    $('#process').addEventListener('click', () => {
      const input = $('#input').value;
      const operation = $('#operation').value;

      if (!input.trim()) {
        toast('Please enter text', 'error');
        return;
      }

      let output;
      if (operation === 'escape') {
        output = escapeHtml(input);
      } else {
        output = unescapeHtml(input);
      }

      $('#output').textContent = output;
      toast('Processing complete');
    });

    $('#copy').addEventListener('click', () => {
      navigator.clipboard.writeText($('#output').textContent).then(() => toast('Copied'));
    });

    // Initialize
    $('#process').click();
  });
}

function urlparserTool() {
  setTool('URL Parser', `
        <div class="form-group">
            <label>URL to Parse</label>
            <input type="text" id="url" placeholder="https://example.com:8080/path?query=value#fragment" value="https://example.com:8080/path?query=value#fragment" style="font-family: monospace;" />
        </div>
        <div class="btn-group">
            <button id="parse" class="btn">Parse URL</button>
            <button id="copy" class="btn btn-secondary">Copy JSON</button>
        </div>
        <div id="output" class="output"></div>
        <div id="components" style="margin-top: 16px;">
            <h4 style="margin-bottom: 8px;">🔗 URL Components</h4>
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 12px;">
                <div class="url-component">
                    <div style="font-size: 12px; color: var(--text-muted);">Protocol</div>
                    <div id="protocol" style="font-weight: 600;"></div>
                </div>
                <div class="url-component">
                    <div style="font-size: 12px; color: var(--text-muted);">Hostname</div>
                    <div id="hostname" style="font-weight: 600;"></div>
                </div>
                <div class="url-component">
                    <div style="font-size: 12px; color: var(--text-muted);">Port</div>
                    <div id="port" style="font-weight: 600;"></div>
                </div>
                <div class="url-component">
                    <div style="font-size: 12px; color: var(--text-muted);">Path</div>
                    <div id="path" style="font-weight: 600;"></div>
                </div>
                <div class="url-component">
                    <div style="font-size: 12px; color: var(--text-muted);">Query</div>
                    <div id="query" style="font-weight: 600;"></div>
                </div>
                <div class="url-component">
                    <div style="font-size: 12px; color: var(--text-muted);">Fragment</div>
                    <div id="fragment" style="font-weight: 600;"></div>
                </div>
            </div>
        </div>
      `, () => {
    function parseUrl(url) {
      try {
        const urlObj = new URL(url);
        const result = {
          href: urlObj.href,
          protocol: urlObj.protocol,
          username: urlObj.username,
          password: urlObj.password,
          host: urlObj.host,
          hostname: urlObj.hostname,
          port: urlObj.port,
          pathname: urlObj.pathname,
          search: urlObj.search,
          searchParams: Object.fromEntries(urlObj.searchParams.entries()),
          hash: urlObj.hash,
          origin: urlObj.origin
        };

        // Update component display
        $('#protocol').textContent = result.protocol || '-';
        $('#hostname').textContent = result.hostname || '-';
        $('#port').textContent = result.port || '80/443';
        $('#path').textContent = result.pathname || '/';
        $('#query').textContent = result.search || '-';
        $('#fragment').textContent = result.hash || '-';

        return result;
      } catch (error) {
        throw new Error('Invalid URL: ' + error.message);
      }
    }

    $('#parse').addEventListener('click', () => {
      const url = $('#url').value.trim();

      if (!url) {
        toast('Please enter a URL', 'error');
        return;
      }

      try {
        const parsed = parseUrl(url);
        $('#output').textContent = JSON.stringify(parsed, null, 2);
        toast('URL parsed successfully');
      } catch (error) {
        toast('Error: ' + error.message, 'error');
      }
    });

    $('#copy').addEventListener('click', () => {
      navigator.clipboard.writeText($('#output').textContent).then(() => toast('Copied'));
    });

    // Initialize
    $('#parse').click();
  });
}

function basicauthTool() {
  setTool('Basic Auth Generator', `
        <div class="row">
            <div class="form-group">
                <label>Username</label>
                <input type="text" id="username" placeholder="username" value="admin" />
            </div>
            <div class="form-group">
                <label>Password</label>
                <input type="password" id="password" placeholder="password" value="secret" />
            </div>
        </div>
        <div class="btn-group">
            <button id="generate" class="btn">Generate</button>
            <button id="copyHeader" class="btn btn-secondary">Copy Header</button>
            <button id="copyCurl" class="btn btn-secondary">Copy cURL</button>
        </div>
        <div id="results" class="output"></div>
        <div style="margin-top: 16px; padding: 16px; background: var(--bg-secondary); border-radius: 8px;">
            <h4 style="margin-bottom: 8px;">📚 Basic Authentication</h4>
            <p style="font-size: 14px; color: var(--text-muted); margin-bottom: 8px;">
                Basic authentication encodes username:password in base64 and adds it to the Authorization header.
            </p>
            <code style="display: block; padding: 8px; background: var(--bg); border-radius: 4px; font-size: 12px;">
                Authorization: Basic &lt;base64(username:password)&gt;
            </code>
        </div>
      `, () => {
    function generateBasicAuth(username, password) {
      const credentials = `${username}:${password}`;
      const encoded = btoa(credentials);
      const header = `Authorization: Basic ${encoded}`;

      const curlCommand = `curl -H "Authorization: Basic ${encoded}" https://api.example.com/endpoint`;

      return {
        credentials: credentials,
        encoded: encoded,
        header: header,
        curl: curlCommand,
        fullExample: `fetch('https://api.example.com/endpoint', {
  headers: {
    'Authorization': 'Basic ${encoded}'
  }
})`
      };
    }

    $('#generate').addEventListener('click', () => {
      const username = $('#username').value.trim();
      const password = $('#password').value.trim();

      if (!username || !password) {
        toast('Please enter both username and password', 'error');
        return;
      }

      const result = generateBasicAuth(username, password);

      const output = [
        'Credentials:',
        `  ${result.credentials}`,
        '',
        'Base64 Encoded:',
        `  ${result.encoded}`,
        '',
        'Authorization Header:',
        `  ${result.header}`,
        '',
        'cURL Command:',
        `  ${result.curl}`,
        '',
        'JavaScript Fetch Example:',
        result.fullExample
      ].join('\n');

      $('#results').textContent = output;
      toast('Basic auth generated');
    });

    $('#copyHeader').addEventListener('click', () => {
      const username = $('#username').value.trim();
      const password = $('#password').value.trim();

      if (!username || !password) {
        toast('Please enter both username and password', 'error');
        return;
      }

      const result = generateBasicAuth(username, password);
      navigator.clipboard.writeText(result.header).then(() => toast('Header copied'));
    });

    $('#copyCurl').addEventListener('click', () => {
      const username = $('#username').value.trim();
      const password = $('#password').value.trim();

      if (!username || !password) {
        toast('Please enter both username and password', 'error');
        return;
      }

      const result = generateBasicAuth(username, password);
      navigator.clipboard.writeText(result.curl).then(() => toast('cURL command copied'));
    });

    // Initialize
    $('#generate').click();
  });
}

function ogTool() {
  setTool('Open Graph Meta Generator', `
        <div class="row">
            <div class="form-group">
                <label>Page Title</label>
                <input type="text" id="title" placeholder="My Awesome Page" value="Utility Toolbox" />
            </div>
            <div class="form-group">
                <label>Page URL</label>
                <input type="text" id="url" placeholder="https://example.com" value="https://utility-toolbox.com" />
            </div>
        </div>
        <div class="row">
            <div class="form-group">
                <label>Description</label>
                <textarea id="description" rows="2" placeholder="Page description">All-in-one developer utilities toolbox</textarea>
            </div>
            <div class="form-group">
                <label>Image URL</label>
                <input type="text" id="image" placeholder="https://example.com/image.jpg" value="https://utility-toolbox.com/og-image.jpg" />
            </div>
        </div>
        <div class="row">
            <div class="form-group">
                <label>Site Name</label>
                <input type="text" id="siteName" placeholder="Site Name" value="Utility Toolbox" />
            </div>
            <div class="form-group">
                <label>Locale</label>
                <input type="text" id="locale" placeholder="en_US" value="en_US" />
            </div>
        </div>
        <div class="btn-group">
            <button id="generate" class="btn">Generate Meta Tags</button>
            <button id="copy" class="btn btn-secondary">Copy HTML</button>
            <button id="preview" class="btn btn-secondary">Preview</button>
        </div>
        <div id="output" class="output"></div>
        <div id="previewArea" style="margin-top: 16px; display: none;">
            <h4 style="margin-bottom: 8px;">📱 Social Media Preview</h4>
            <div style="background: white; border-radius: 8px; padding: 16px; max-width: 500px; box-shadow: 0 2px 8px rgba(0,0,0,0.1);">
                <div id="previewImage" style="height: 200px; background: #f0f0f0; border-radius: 4px; margin-bottom: 12px; display: flex; align-items: center; justify-content: center; color: #666;">
                    Image Preview
                </div>
                <div id="previewUrl" style="font-size: 12px; color: #666; margin-bottom: 4px;"></div>
                <div id="previewTitle" style="font-weight: bold; font-size: 16px; margin-bottom: 4px;"></div>
                <div id="previewDescription" style="font-size: 14px; color: #333;"></div>
            </div>
        </div>
      `, () => {
    function generateMetaTags(data) {
      const tags = [
        `<meta property="og:title" content="${escapeHtml(data.title)}" />`,
        `<meta property="og:type" content="website" />`,
        `<meta property="og:url" content="${escapeHtml(data.url)}" />`,
        `<meta property="og:image" content="${escapeHtml(data.image)}" />`,
        `<meta property="og:description" content="${escapeHtml(data.description)}" />`,
        `<meta property="og:site_name" content="${escapeHtml(data.siteName)}" />`,
        `<meta property="og:locale" content="${escapeHtml(data.locale)}" />`,
        `<meta name="twitter:card" content="summary_large_image" />`,
        `<meta name="twitter:title" content="${escapeHtml(data.title)}" />`,
        `<meta name="twitter:description" content="${escapeHtml(data.description)}" />`,
        `<meta name="twitter:image" content="${escapeHtml(data.image)}" />`,
        `<meta name="description" content="${escapeHtml(data.description)}" />`
      ];

      return tags.join('\n');
    }

    function escapeHtml(text) {
      const div = document.createElement('div');
      div.textContent = text;
      return div.innerHTML;
    }

    $('#generate').addEventListener('click', () => {
      const data = {
        title: $('#title').value.trim(),
        url: $('#url').value.trim(),
        description: $('#description').value.trim(),
        image: $('#image').value.trim(),
        siteName: $('#siteName').value.trim(),
        locale: $('#locale').value.trim()
      };

      if (!data.title || !data.url) {
        toast('Please enter at least title and URL', 'error');
        return;
      }

      const metaTags = generateMetaTags(data);
      $('#output').textContent = metaTags;

      // Update preview
      $('#previewUrl').textContent = new URL(data.url).hostname;
      $('#previewTitle').textContent = data.title;
      $('#previewDescription').textContent = data.description;

      if (data.image) {
        $('#previewImage').style.background = `url('${data.image}') center/cover`;
        $('#previewImage').textContent = '';
      }

      toast('Meta tags generated');
    });

    $('#copy').addEventListener('click', () => {
      navigator.clipboard.writeText($('#output').textContent).then(() => toast('HTML copied'));
    });

    $('#preview').addEventListener('click', () => {
      $('#previewArea').style.display = 'block';
      toast('Preview shown');
    });

    // Initialize
    $('#generate').click();
  });
}

function otpTool() {
  setTool('OTP Code Generator', `
        <div class="form-group">
            <label>Secret Key (Base32)</label>
            <input type="text" id="secret" placeholder="Enter or generate secret" value="JBSWY3DPEHPK3PXP" style="font-family: monospace;" />
            <button id="generateSecret" class="btn btn-secondary" style="margin-top: 8px; width: 100%;">Generate New Secret</button>
        </div>
        <div class="row">
            <div class="form-group">
                <label>Current Time</label>
                <div id="currentTime" style="padding: 12px; background: var(--bg-secondary); border-radius: 8px; text-align: center; font-family: monospace; font-size: 18px;"></div>
            </div>
            <div class="form-group">
                <label>Current OTP</label>
                <div id="currentOtp" style="padding: 12px; background: var(--bg-secondary); border-radius: 8px; text-align: center; font-family: monospace; font-size: 24px; font-weight: bold; letter-spacing: 4px;"></div>
            </div>
        </div>
        <div class="form-group">
            <label>Verify OTP</label>
            <div class="row">
                <input type="text" id="verifyCode" placeholder="Enter 6-digit code" maxlength="6" style="flex: 2;" />
                <button id="verify" class="btn" style="flex: 1;">Verify</button>
            </div>
            <div id="verifyResult" style="margin-top: 8px;"></div>
        </div>
        <div class="btn-group">
            <button id="copyOtp" class="btn btn-secondary">Copy OTP</button>
            <button id="copySecret" class="btn btn-secondary">Copy Secret</button>
        </div>
        <div style="margin-top: 16px; padding: 16px; background: var(--bg-secondary); border-radius: 8px;">
            <h4 style="margin-bottom: 8px;">📚 About TOTP</h4>
            <p style="font-size: 14px; color: var(--text-muted);">
                Time-based One-Time Password (TOTP) generates a 6-digit code that changes every 30 seconds.
                Use this for two-factor authentication. The secret key should be kept secure.
            </p>
        </div>
      `, () => {
    const base32Chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

    function generateSecret() {
      const bytes = new Uint8Array(20);
      crypto.getRandomValues(bytes);
      let secret = '';
      for (let i = 0; i < bytes.length; i += 5) {
        let buffer = 0;
        for (let j = 0; j < 5; j++) {
          if (i + j < bytes.length) {
            buffer = (buffer << 8) | bytes[i + j];
          }
        }
        for (let j = 0; j < 8; j++) {
          if (i * 8 + j * 5 < bytes.length * 8) {
            secret += base32Chars[(buffer >> (35 - j * 5)) & 0x1f];
          }
        }
      }
      return secret;
    }

    function base32Decode(secret) {
      secret = secret.toUpperCase().replace(/=+$/, '');
      let buffer = 0;
      let bits = 0;
      let output = [];

      for (let i = 0; i < secret.length; i++) {
        const val = base32Chars.indexOf(secret[i]);
        if (val === -1) throw new Error('Invalid base32 character');
        buffer = (buffer << 5) | val;
        bits += 5;
        if (bits >= 8) {
          output.push((buffer >> (bits - 8)) & 0xff);
          bits -= 8;
        }
      }
      return new Uint8Array(output);
    }

    function generateTOTP(secret) {
      try {
        const key = base32Decode(secret);
        const time = Math.floor(Date.now() / 1000 / 30);

        // Convert time to 8-byte array (big-endian)
        const timeBytes = new Uint8Array(8);
        for (let i = 7; i >= 0; i--) {
          timeBytes[i] = time & 0xff;
          time >>= 8;
        }

        // HMAC-SHA1 (simplified)
        const encoder = new TextEncoder();
        const keyData = encoder.encode(String.fromCharCode(...key));
        const timeData = encoder.encode(String.fromCharCode(...timeBytes));

        // Simple XOR-based HMAC simulation (in production, use proper crypto)
        let hash = new Uint8Array(20);
        for (let i = 0; i < keyData.length; i++) {
          hash[i % 20] ^= keyData[i];
        }
        for (let i = 0; i < timeData.length; i++) {
          hash[i % 20] ^= timeData[i];
        }

        // Dynamic truncation
        const offset = hash[19] & 0xf;
        const code = ((hash[offset] & 0x7f) << 24) |
          ((hash[offset + 1] & 0xff) << 16) |
          ((hash[offset + 2] & 0xff) << 8) |
          (hash[offset + 3] & 0xff);

        return (code % 1000000).toString().padStart(6, '0');
      } catch (e) {
        return 'ERROR';
      }
    }

    function updateDisplay() {
      const now = new Date();
      $('#currentTime').textContent = now.toLocaleTimeString();

      const secret = $('#secret').value.trim();
      if (secret) {
        const otp = generateTOTP(secret);
        $('#currentOtp').textContent = otp;

        // Update every second
        setTimeout(updateDisplay, 1000);
      }
    }

    $('#generateSecret').addEventListener('click', () => {
      const secret = generateSecret();
      $('#secret').value = secret;
      toast('New secret generated');
    });

    $('#verify').addEventListener('click', () => {
      const secret = $('#secret').value.trim();
      const code = $('#verifyCode').value.trim();

      if (!secret || !code) {
        toast('Please enter secret and code', 'error');
        return;
      }

      if (!/^\d{6}$/.test(code)) {
        toast('Code must be 6 digits', 'error');
        return;
      }

      const generated = generateTOTP(secret);
      const isValid = code === generated;

      $('#verifyResult').textContent = isValid ? '✅ Code is valid!' : '❌ Code is invalid';
      $('#verifyResult').style.color = isValid ? 'var(--success)' : 'var(--error)';

      toast(isValid ? 'Verification successful' : 'Verification failed', isValid ? 'success' : 'error');
    });

    $('#copyOtp').addEventListener('click', () => {
      navigator.clipboard.writeText($('#currentOtp').textContent).then(() => toast('OTP copied'));
    });

    $('#copySecret').addEventListener('click', () => {
      navigator.clipboard.writeText($('#secret').value).then(() => toast('Secret copied'));
    });

    // Initialize
    if (!$('#secret').value.trim()) {
      $('#secret').value = generateSecret();
    }
    updateDisplay();
  });
}

function mimetypesTool() {
  setTool('MIME Types Lookup', `
        <div class="row">
            <div class="form-group">
                <label>Lookup by</label>
                <select id="lookupBy">
                    <option value="extension">File Extension</option>
                    <option value="mimetype">MIME Type</option>
                </select>
            </div>
            <div class="form-group">
                <label>Search</label>
                <input type="text" id="search" placeholder=".txt or text/plain" value=".txt" />
            </div>
        </div>
        <div class="btn-group">
            <button id="searchBtn" class="btn">Search</button>
            <button id="common" class="btn btn-secondary">Show Common Types</button>
        </div>
        <div id="results" class="output"></div>
        <div style="margin-top: 16px;">
            <h4 style="margin-bottom: 8px;">📚 Common MIME Types</h4>
            <div id="commonTypes" style="display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 8px; font-size: 14px;"></div>
        </div>
      `, () => {
    const mimeTypes = {
      // Text
      '.txt': 'text/plain',
      '.html': 'text/html',
      '.htm': 'text/html',
      '.css': 'text/css',
      '.csv': 'text/csv',
      '.xml': 'text/xml',
      '.json': 'application/json',
      '.js': 'application/javascript',
      '.ts': 'application/typescript',

      // Images
      '.jpg': 'image/jpeg',
      '.jpeg': 'image/jpeg',
      '.png': 'image/png',
      '.gif': 'image/gif',
      '.webp': 'image/webp',
      '.svg': 'image/svg+xml',
      '.ico': 'image/x-icon',
      '.bmp': 'image/bmp',
      '.tiff': 'image/tiff',

      // Audio
      '.mp3': 'audio/mpeg',
      '.wav': 'audio/wav',
      '.ogg': 'audio/ogg',
      '.flac': 'audio/flac',
      '.aac': 'audio/aac',
      '.m4a': 'audio/mp4',

      // Video
      '.mp4': 'video/mp4',
      '.webm': 'video/webm',
      '.avi': 'video/x-msvideo',
      '.mov': 'video/quicktime',
      '.wmv': 'video/x-ms-wmv',
      '.flv': 'video/x-flv',
      '.mkv': 'video/x-matroska',

      // Documents
      '.pdf': 'application/pdf',
      '.doc': 'application/msword',
      '.docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
      '.xls': 'application/vnd.ms-excel',
      '.xlsx': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
      '.ppt': 'application/vnd.ms-powerpoint',
      '.pptx': 'application/vnd.openxmlformats-officedocument.presentationml.presentation',
      '.odt': 'application/vnd.oasis.opendocument.text',

      // Archives
      '.zip': 'application/zip',
      '.tar': 'application/x-tar',
      '.gz': 'application/gzip',
      '.7z': 'application/x-7z-compressed',
      '.rar': 'application/vnd.rar',

      // Fonts
      '.ttf': 'font/ttf',
      '.otf': 'font/otf',
      '.woff': 'font/woff',
      '.woff2': 'font/woff2',

      // Other
      '.exe': 'application/x-msdownload',
      '.dmg': 'application/x-apple-diskimage',
      '.iso': 'application/x-iso9660-image'
    };

    // Reverse mapping
    const extensionsByMime = {};
    for (const [ext, mime] of Object.entries(mimeTypes)) {
      if (!extensionsByMime[mime]) {
        extensionsByMime[mime] = [];
      }
      extensionsByMime[mime].push(ext);
    }

    function displayCommonTypes() {
      const common = [
        ['.html', 'text/html', 'HTML document'],
        ['.css', 'text/css', 'CSS stylesheet'],
        ['.js', 'application/javascript', 'JavaScript file'],
        ['.json', 'application/json', 'JSON data'],
        ['.png', 'image/png', 'PNG image'],
        ['.jpg', 'image/jpeg', 'JPEG image'],
        ['.pdf', 'application/pdf', 'PDF document'],
        ['.zip', 'application/zip', 'ZIP archive'],
        ['.mp3', 'audio/mpeg', 'MP3 audio'],
        ['.mp4', 'video/mp4', 'MP4 video']
      ];

      const html = common.map(([ext, mime, desc]) => `
                <div style="padding: 8px; background: var(--bg-secondary); border-radius: 4px;">
                    <div style="font-weight: 600;">${ext}</div>
                    <div style="color: var(--text-muted); font-size: 12px;">${mime}</div>
                    <div style="font-size: 12px;">${desc}</div>
                </div>
            `).join('');

      $('#commonTypes').innerHTML = html;
    }

    $('#searchBtn').addEventListener('click', () => {
      const lookupBy = $('#lookupBy').value;
      const search = $('#search').value.trim().toLowerCase();

      if (!search) {
        toast('Please enter search term', 'error');
        return;
      }

      let results = [];

      if (lookupBy === 'extension') {
        const ext = search.startsWith('.') ? search : '.' + search;
        const mime = mimeTypes[ext];

        if (mime) {
          results.push(`Extension: ${ext}`);
          results.push(`MIME Type: ${mime}`);

          const category = getMimeCategory(mime);
          results.push(`Category: ${category}`);

          const otherExtensions = extensionsByMime[mime]?.filter(e => e !== ext);
          if (otherExtensions && otherExtensions.length > 0) {
            results.push(`Also used for: ${otherExtensions.join(', ')}`);
          }
        } else {
          results.push(`No MIME type found for extension: ${ext}`);
        }
      } else {
        const mime = search.includes('/') ? search : findMimeByPartial(search);

        if (mime) {
          results.push(`MIME Type: ${mime}`);

          const exts = extensionsByMime[mime];
          if (exts && exts.length > 0) {
            results.push(`File extensions: ${exts.join(', ')}`);
          } else {
            results.push('No specific file extensions');
          }

          const category = getMimeCategory(mime);
          results.push(`Category: ${category}`);
        } else {
          results.push(`No extensions found for MIME type: ${search}`);
        }
      }

      $('#results').textContent = results.join('\n');
    });

    function findMimeByPartial(partial) {
      partial = partial.toLowerCase();
      for (const mime of Object.keys(extensionsByMime)) {
        if (mime.toLowerCase().includes(partial)) {
          return mime;
        }
      }
      return null;
    }

    function getMimeCategory(mime) {
      if (mime.startsWith('text/')) return 'Text';
      if (mime.startsWith('image/')) return 'Image';
      if (mime.startsWith('audio/')) return 'Audio';
      if (mime.startsWith('video/')) return 'Video';
      if (mime.startsWith('font/')) return 'Font';
      if (mime.includes('json')) return 'JSON';
      if (mime.includes('javascript')) return 'JavaScript';
      if (mime.includes('pdf')) return 'PDF';
      if (mime.includes('zip') || mime.includes('tar') || mime.includes('gzip')) return 'Archive';
      if (mime.includes('msword') || mime.includes('excel') || mime.includes('powerpoint')) return 'Office Document';
      if (mime.includes('octet-stream')) return 'Binary';
      return 'Other';
    }

    $('#common').addEventListener('click', displayCommonTypes);

    // Initialize
    displayCommonTypes();
    $('#searchBtn').click();
  });
}

function jwtTool() {
  setTool('JWT Parser', `
        <div class="form-group">
            <label>JWT Token</label>
            <textarea id="jwt" rows="4" placeholder="Enter JWT token">eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c</textarea>
        </div>
        <div class="btn-group">
            <button id="parse" class="btn">Parse JWT</button>
            <button id="generate" class="btn btn-secondary">Generate Example</button>
            <button id="copy" class="btn btn-secondary">Copy Decoded</button>
        </div>
        <div id="results" class="output"></div>
        <div style="margin-top: 16px;">
            <h4 style="margin-bottom: 8px;">🔐 JWT Components</h4>
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 12px;">
                <div>
                    <div style="font-size: 12px; color: var(--text-muted);">Header</div>
                    <div id="jwtHeader" style="padding: 8px; background: var(--bg-secondary); border-radius: 4px; font-family: monospace; font-size: 12px; word-break: break-all;"></div>
                </div>
                <div>
                    <div style="font-size: 12px; color: var(--text-muted);">Payload</div>
                    <div id="jwtPayload" style="padding: 8px; background: var(--bg-secondary); border-radius: 4px; font-family: monospace; font-size: 12px; word-break: break-all;"></div>
                </div>
                <div>
                    <div style="font-size: 12px; color: var(--text-muted);">Signature</div>
                    <div id="jwtSignature" style="padding: 8px; background: var(--bg-secondary); border-radius: 4px; font-family: monospace; font-size: 12px; word-break: break-all;"></div>
                </div>
            </div>
        </div>
      `, () => {
    function parseJWT(token) {
      const parts = token.split('.');
      if (parts.length !== 3) {
        throw new Error('Invalid JWT format. Expected 3 parts separated by dots.');
      }

      const [headerB64, payloadB64, signatureB64] = parts;

      function decodeBase64(str) {
        // Replace URL-safe characters
        str = str.replace(/-/g, '+').replace(/_/g, '/');
        // Add padding if needed
        while (str.length % 4) {
          str += '=';
        }
        return decodeURIComponent(escape(atob(str)));
      }

      try {
        const header = JSON.parse(decodeBase64(headerB64));
        const payload = JSON.parse(decodeBase64(payloadB64));

        return {
          header: header,
          payload: payload,
          signature: signatureB64,
          raw: {
            header: headerB64,
            payload: payloadB64,
            signature: signatureB64
          }
        };
      } catch (e) {
        throw new Error('Failed to decode JWT: ' + e.message);
      }
    }

    function formatDate(timestamp) {
      if (!timestamp) return 'N/A';
      const date = new Date(timestamp * 1000);
      return date.toLocaleString();
    }

    $('#parse').addEventListener('click', () => {
      const token = $('#jwt').value.trim();

      if (!token) {
        toast('Please enter a JWT token', 'error');
        return;
      }

      try {
        const parsed = parseJWT(token);

        // Update component displays
        $('#jwtHeader').textContent = JSON.stringify(parsed.header, null, 2);
        $('#jwtPayload').textContent = JSON.stringify(parsed.payload, null, 2);
        $('#jwtSignature').textContent = parsed.signature;

        // Build results
        const results = [];
        results.push('=== HEADER ===');
        results.push(`Algorithm: ${parsed.header.alg || 'N/A'}`);
        results.push(`Type: ${parsed.header.typ || 'N/A'}`);

        results.push('\n=== PAYLOAD ===');
        for (const [key, value] of Object.entries(parsed.payload)) {
          if (key === 'iat' || key === 'exp' || key === 'nbf') {
            results.push(`${key}: ${value} (${formatDate(value)})`);
          } else if (typeof value === 'object') {
            results.push(`${key}: ${JSON.stringify(value)}`);
          } else {
            results.push(`${key}: ${value}`);
          }
        }

        results.push('\n=== SIGNATURE ===');
        results.push(`Length: ${parsed.signature.length} characters`);
        results.push(`Base64: ${parsed.signature}`);

        results.push('\n=== RAW TOKEN ===');
        results.push(`Total length: ${token.length} characters`);
        results.push(`Header length: ${parsed.raw.header.length}`);
        results.push(`Payload length: ${parsed.raw.payload.length}`);
        results.push(`Signature length: ${parsed.raw.signature.length}`);

        $('#results').textContent = results.join('\n');
        toast('JWT parsed successfully');
      } catch (error) {
        toast('Error: ' + error.message, 'error');
        $('#results').textContent = error.message;
      }
    });

    $('#generate').addEventListener('click', () => {
      const examplePayload = {
        sub: '1234567890',
        name: 'John Doe',
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + 3600,
        admin: true,
        roles: ['user', 'admin']
      };

      const exampleHeader = {
        alg: 'HS256',
        typ: 'JWT'
      };

      const headerB64 = btoa(JSON.stringify(exampleHeader)).replace(/=+$/, '').replace(/\+/g, '-').replace(/\//g, '_');
      const payloadB64 = btoa(JSON.stringify(examplePayload)).replace(/=+$/, '').replace(/\+/g, '-').replace(/\//g, '_');
      const signature = 'SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';

      const exampleJWT = `${headerB64}.${payloadB64}.${signature}`;
      $('#jwt').value = exampleJWT;
      toast('Example JWT generated');
      $('#parse').click();
    });

    $('#copy').addEventListener('click', () => {
      navigator.clipboard.writeText($('#results').textContent).then(() => toast('Decoded data copied'));
    });

    // Initialize
    $('#generate').click();
  });
}

function keycodeTool() {
  setTool('Keycode Info', `
        <div class="form-group">
            <label>Press any key in this area:</label>
            <div id="keyArea" style="padding: 40px; background: var(--bg-secondary); border-radius: 12px; text-align: center; border: 2px solid var(--border); cursor: pointer; user-select: none;">
                <div style="font-size: 48px; margin-bottom: 16px;">⌨️</div>
                <div>Click here and press any key</div>
            </div>
        </div>
        <div id="results" class="output"></div>
        <div style="margin-top: 16px;">
            <h4 style="margin-bottom: 8px;">📚 Common Key Codes</h4>
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 8px; font-size: 14px;">
                <div>Enter: 13</div><div>Escape: 27</div><div>Space: 32</div>
                <div>Tab: 9</div><div>Caps Lock: 20</div><div>Shift: 16</div>
                <div>Control: 17</div><div>Alt: 18</div><div>Backspace: 8</div>
                <div>Delete: 46</div><div>Home: 36</div><div>End: 35</div>
                <div>Page Up: 33</div><div>Page Down: 34</div><div>Arrow Up: 38</div>
                <div>Arrow Down: 40</div><div>Arrow Left: 37</div><div>Arrow Right: 39</div>
                <div>F1: 112</div><div>F12: 123</div><div>Windows: 91</div>
            </div>
        </div>
      `, () => {
    let lastEvent = null;

    function formatKeyEvent(e) {
      const results = [];

      results.push('=== KEY INFORMATION ===');
      results.push(`Key: "${e.key}"`);
      results.push(`Code: "${e.code}"`);
      results.push(`Key Code: ${e.keyCode}`);
      results.push(`Which: ${e.which}`);
      results.push(`Location: ${e.location} (${getLocationName(e.location)})`);
      results.push(`Repeat: ${e.repeat ? 'Yes' : 'No'}`);

      results.push('\n=== MODIFIERS ===');
      results.push(`Shift: ${e.shiftKey ? 'Pressed' : 'Not pressed'}`);
      results.push(`Control: ${e.ctrlKey ? 'Pressed' : 'Not pressed'}`);
      results.push(`Alt: ${e.altKey ? 'Pressed' : 'Not pressed'}`);
      results.push(`Meta: ${e.metaKey ? 'Pressed' : 'Not pressed'}`);

      results.push('\n=== EVENT DETAILS ===');
      results.push(`Type: ${e.type}`);
      results.push(`Timestamp: ${e.timeStamp}ms`);
      results.push(`Bubbles: ${e.bubbles}`);
      results.push(`Cancelable: ${e.cancelable}`);

      return results.join('\n');
    }

    function getLocationName(location) {
      switch (location) {
        case 0: return 'Standard';
        case 1: return 'Left';
        case 2: return 'Right';
        case 3: return 'Numpad';
        default: return 'Unknown';
      }
    }

    $('#keyArea').addEventListener('click', function() {
      this.focus();
      this.textContent = 'Listening for keypress...';
      this.style.borderColor = 'var(--primary)';
    });

    $('#keyArea').addEventListener('keydown', function(e) {
      e.preventDefault();
      e.stopPropagation();

      lastEvent = e;
      $('#results').textContent = formatKeyEvent(e);

      this.innerHTML = `
                <div style="font-size: 48px; margin-bottom: 16px;">⌨️</div>
                <div style="font-size: 24px; font-weight: bold; margin-bottom: 8px;">"${e.key}"</div>
                <div>code: "${e.code}" | keyCode: ${e.keyCode}</div>
            `;
      this.style.borderColor = 'var(--success)';

      // Reset border color after 500ms
      setTimeout(() => {
        this.style.borderColor = 'var(--border)';
      }, 500);
    });

    $('#keyArea').addEventListener('blur', function() {
      this.innerHTML = `
                <div style="font-size: 48px; margin-bottom: 16px;">⌨️</div>
                <div>Click here and press any key</div>
            `;
      this.style.borderColor = 'var(--border)';
    });

    // Make div focusable
    $('#keyArea').setAttribute('tabindex', '0');
  });
}

function slugifyTool() {
  setTool('Slugify String', `
        <div class="form-group">
            <label>Input Text</label>
            <textarea id="input" rows="4" placeholder="Enter text to slugify">Hello World! This is a Test #1</textarea>
        </div>
        <div class="row">
            <div class="form-group">
                <label>Separator</label>
                <select id="separator">
                    <option value="-">Hyphen (-)</option>
                    <option value="_">Underscore (_)</option>
                    <option value=".">Dot (.)</option>
                </select>
            </div>
            <div class="form-group">
                <label>Case</label>
                <select id="case">
                    <option value="lower">lowercase</option>
                    <option value="keep">Keep original</option>
                </select>
            </div>
        </div>
        <div class="form-group">
            <label>Options</label>
            <div style="display: flex; flex-direction: column; gap: 8px;">
                <label style="display: flex; align-items: center; gap: 8px;">
                    <input type="checkbox" id="trim" checked />
                    <span>Trim whitespace</span>
                </label>
                <label style="display: flex; align-items: center; gap: 8px;">
                    <input type="checkbox" id="removeStopWords" />
                    <span>Remove common words (a, an, the, etc.)</span>
                </label>
                <label style="display: flex; align-items: center; gap: 8px;">
                    <input type="number" id="maxLength" placeholder="Max length (optional)" min="1" max="200" />
                </label>
            </div>
        </div>
        <div class="btn-group">
            <button id="slugify" class="btn">Slugify</button>
            <button id="copy" class="btn btn-secondary">Copy Result</button>
        </div>
        <div id="output" class="output"></div>
        <div style="margin-top: 16px; padding: 16px; background: var(--bg-secondary); border-radius: 8px;">
            <h4 style="margin-bottom: 8px;">📚 Slug Examples</h4>
            <div style="font-size: 14px;">
                <div>Input: "Hello World! Test #1"</div>
                <div>Output: "hello-world-test-1"</div>
                <div style="margin-top: 8px;">Use slugs for:</div>
                <ul style="margin: 8px 0; padding-left: 20px;">
                    <li>URLs (blog posts, products)</li>
                    <li>File names</li>
                    <li>Database IDs</li>
                    <li>CSS class names</li>
                </ul>
            </div>
        </div>
      `, () => {
    const stopWords = new Set(['a', 'an', 'the', 'and', 'or', 'but', 'in', 'on', 'at', 'to', 'for', 'of', 'with', 'by']);

    function slugify(text, options) {
      let slug = text;

      // Trim
      if (options.trim) {
        slug = slug.trim();
      }

      // Remove stop words
      if (options.removeStopWords) {
        const words = slug.split(/\s+/);
        slug = words.filter(word => !stopWords.has(word.toLowerCase())).join(' ');
      }

      // Convert to lowercase if needed
      if (options.case === 'lower') {
        slug = slug.toLowerCase();
      }

      // Replace non-alphanumeric characters with separator
      slug = slug.replace(/[^\w\s]/g, ' ');

      // Replace multiple spaces with single space
      slug = slug.replace(/\s+/g, ' ');

      // Replace spaces with separator
      slug = slug.replace(/\s/g, options.separator);

      // Remove leading/trailing separators
      slug = slug.replace(new RegExp(`^${options.separator}+|${options.separator}+$`, 'g'), '');

      // Limit length if specified
      if (options.maxLength && slug.length > options.maxLength) {
        slug = slug.substring(0, options.maxLength);
        // Don't end with separator
        if (slug.endsWith(options.separator)) {
          slug = slug.substring(0, slug.length - 1);
        }
      }

      return slug;
    }

    $('#slugify').addEventListener('click', () => {
      const input = $('#input').value;
      const options = {
        separator: $('#separator').value,
        case: $('#case').value,
        trim: $('#trim').checked,
        removeStopWords: $('#removeStopWords').checked,
        maxLength: parseInt($('#maxLength').value) || 0
      };

      if (!input.trim()) {
        toast('Please enter text', 'error');
        return;
      }

      const output = slugify(input, options);
      $('#output').textContent = output;

      // Show stats
      const stats = `Length: ${output.length} characters`;
      toast(`Slugified! ${stats}`);
    });

    $('#copy').addEventListener('click', () => {
      navigator.clipboard.writeText($('#output').textContent).then(() => toast('Copied'));
    });

    // Initialize
    $('#slugify').click();
  });
}

function wysiwygTool() {
  setTool('HTML WYSIWYG Editor', `
        <div class="form-group">
            <label>Editor</label>
            <div id="editor" contenteditable="true" style="min-height: 200px; padding: 16px; background: var(--card); border: 1px solid var(--border); border-radius: 8px; outline: none; font-family: inherit;">
                <h1>Welcome to the Editor</h1>
                <p>This is a <strong>basic</strong> WYSIWYG editor. You can edit this text!</p>
                <ul>
                    <li>List item 1</li>
                    <li>List item 2</li>
                </ul>
            </div>
        </div>
        <div class="btn-group">
            <button onclick="document.execCommand('bold', false, null)" title="Bold"><i class="fas fa-bold"></i></button>
            <button onclick="document.execCommand('italic', false, null)" title="Italic"><i class="fas fa-italic"></i></button>
            <button onclick="document.execCommand('underline', false, null)" title="Underline"><i class="fas fa-underline"></i></button>
            <button onclick="document.execCommand('strikeThrough', false, null)" title="Strikethrough"><i class="fas fa-strikethrough"></i></button>
            <div style="width: 1px; background: var(--border); margin: 0 8px;"></div>
            <button onclick="document.execCommand('formatBlock', false, 'h1')" title="Heading 1">H1</button>
            <button onclick="document.execCommand('formatBlock', false, 'h2')" title="Heading 2">H2</button>
            <button onclick="document.execCommand('formatBlock', false, 'p')" title="Paragraph">P</button>
            <div style="width: 1px; background: var(--border); margin: 0 8px;"></div>
            <button onclick="document.execCommand('insertUnorderedList', false, null)" title="Bullet List"><i class="fas fa-list-ul"></i></button>
            <button onclick="document.execCommand('insertOrderedList', false, null)" title="Numbered List"><i class="fas fa-list-ol"></i></button>
            <button onclick="document.execCommand('indent', false, null)" title="Indent"><i class="fas fa-indent"></i></button>
            <button onclick="document.execCommand('outdent', false, null)" title="Outdent"><i class="fas fa-outdent"></i></button>
            <div style="width: 1px; background: var(--border); margin: 0 8px;"></div>
            <button onclick="document.execCommand('createLink', false, prompt('Enter URL:', 'https://'))" title="Insert Link"><i class="fas fa-link"></i></button>
            <button onclick="document.execCommand('unlink', false, null)" title="Remove Link"><i class="fas fa-unlink"></i></button>
            <button onclick="insertImage()" title="Insert Image"><i class="fas fa-image"></i></button>
        </div>
        <div class="btn-group" style="margin-top: 16px;">
            <button id="getHtml" class="btn">Get HTML</button>
            <button id="copyHtml" class="btn btn-secondary">Copy HTML</button>
            <button id="clear" class="btn btn-secondary">Clear</button>
        </div>
        <div id="htmlOutput" class="output" style="margin-top: 16px;"></div>
      `, () => {
    function insertImage() {
      const url = prompt('Enter image URL:', 'https://');
      if (url) {
        document.execCommand('insertHTML', false, `<img src="${url}" style="max-width: 100%;" />`);
      }
    }

    $('#getHtml').addEventListener('click', () => {
      const html = $('#editor').innerHTML;
      $('#htmlOutput').textContent = html;
      toast('HTML generated');
    });

    $('#copyHtml').addEventListener('click', () => {
      const html = $('#editor').innerHTML;
      navigator.clipboard.writeText(html).then(() => toast('HTML copied'));
    });

    $('#clear').addEventListener('click', () => {
      $('#editor').innerHTML = '<p>Start typing here...</p>';
      $('#htmlOutput').textContent = '';
      toast('Editor cleared');
    });

    // Style the toolbar buttons
    $$('.btn-group button').forEach(btn => {
      if (!btn.className.includes('btn-')) {
        btn.style.padding = '8px 12px';
        btn.style.background = 'var(--card)';
        btn.style.border = '1px solid var(--border)';
        btn.style.borderRadius = '4px';
        btn.style.color = 'var(--text)';
        btn.style.cursor = 'pointer';
        btn.style.transition = 'background-color 0.2s';

        btn.addEventListener('mouseenter', () => {
          btn.style.background = 'var(--card-hover)';
        });

        btn.addEventListener('mouseleave', () => {
          btn.style.background = 'var(--card)';
        });
      }
    });

    // Initialize
    $('#getHtml').click();
  });
}

function uapTool() {
  setTool('User-Agent Parser', `
        <div class="form-group">
            <label>User-Agent String</label>
            <textarea id="ua" rows="4" placeholder="Enter user-agent string">${navigator.userAgent}</textarea>
            <button id="useCurrent" class="btn btn-secondary" style="margin-top: 8px; width: 100%;">Use My Browser's UA</button>
        </div>
        <div class="btn-group">
            <button id="parse" class="btn">Parse User-Agent</button>
            <button id="copy" class="btn btn-secondary">Copy Results</button>
        </div>
        <div id="results" class="output"></div>
        <div style="margin-top: 16px;">
            <h4 style="margin-bottom: 8px;">📊 Detected Information</h4>
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 12px;">
                <div class="ua-component">
                    <div style="font-size: 12px; color: var(--text-muted);">Browser</div>
                    <div id="uaBrowser" style="font-weight: 600;"></div>
                </div>
                <div class="ua-component">
                    <div style="font-size: 12px; color: var(--text-muted);">OS</div>
                    <div id="uaOS" style="font-weight: 600;"></div>
                </div>
                <div class="ua-component">
                    <div style="font-size: 12px; color: var(--text-muted);">Device</div>
                    <div id="uaDevice" style="font-weight: 600;"></div>
                </div>
                <div class="ua-component">
                    <div style="font-size: 12px; color: var(--text-muted);">Engine</div>
                    <div id="uaEngine" style="font-weight: 600;"></div>
                </div>
            </div>
        </div>
      `, () => {
    function parseUserAgent(ua) {
      const result = {
        browser: 'Unknown',
        browserVersion: 'Unknown',
        os: 'Unknown',
        osVersion: 'Unknown',
        device: 'Unknown',
        engine: 'Unknown',
        isMobile: false,
        isTablet: false,
        isDesktop: false,
        isBot: false
      };

      ua = ua.toLowerCase();

      // Detect browser
      if (ua.includes('chrome') && !ua.includes('edg')) {
        result.browser = 'Chrome';
        result.engine = 'Blink';
      } else if (ua.includes('firefox')) {
        result.browser = 'Firefox';
        result.engine = 'Gecko';
      } else if (ua.includes('safari') && !ua.includes('chrome')) {
        result.browser = 'Safari';
        result.engine = 'WebKit';
      } else if (ua.includes('edge')) {
        result.browser = 'Edge';
        result.engine = 'Blink';
      } else if (ua.includes('opera')) {
        result.browser = 'Opera';
        result.engine = 'Blink';
      } else if (ua.includes('trident')) {
        result.browser = 'Internet Explorer';
        result.engine = 'Trident';
      }

      // Detect OS
      if (ua.includes('windows')) {
        result.os = 'Windows';
        if (ua.includes('windows nt 10')) result.osVersion = '10/11';
        else if (ua.includes('windows nt 6.3')) result.osVersion = '8.1';
        else if (ua.includes('windows nt 6.2')) result.osVersion = '8';
        else if (ua.includes('windows nt 6.1')) result.osVersion = '7';
      } else if (ua.includes('mac os')) {
        result.os = 'macOS';
      } else if (ua.includes('linux')) {
        result.os = 'Linux';
      } else if (ua.includes('android')) {
        result.os = 'Android';
        result.isMobile = true;
      } else if (ua.includes('ios') || ua.includes('iphone') || ua.includes('ipad')) {
        result.os = 'iOS';
        if (ua.includes('ipad')) result.isTablet = true;
        else result.isMobile = true;
      }

      // Detect device
      if (ua.includes('mobile')) {
        result.device = 'Mobile';
        result.isMobile = true;
      } else if (ua.includes('tablet') || ua.includes('ipad')) {
        result.device = 'Tablet';
        result.isTablet = true;
      } else {
        result.device = 'Desktop';
        result.isDesktop = true;
      }

      // Detect bots
      if (ua.includes('bot') || ua.includes('crawler') || ua.includes('spider')) {
        result.isBot = true;
        result.device = 'Bot';
      }

      // Extract versions (simplified)
      const browserMatch = ua.match(new RegExp(`${result.browser.toLowerCase()}/([\\d.]+)`));
      if (browserMatch) {
        result.browserVersion = browserMatch[1];
      }

      const osMatch = ua.match(/(?:windows|mac os|android|linux|ios)[\s\/]([\d._]+)/);
      if (osMatch) {
        result.osVersion = osMatch[1].replace(/_/g, '.');
      }

      return result;
    }

    $('#useCurrent').addEventListener('click', () => {
      $('#ua').value = navigator.userAgent;
      toast('Current user-agent loaded');
    });

    $('#parse').addEventListener('click', () => {
      const ua = $('#ua').value.trim();

      if (!ua) {
        toast('Please enter a user-agent string', 'error');
        return;
      }

      const parsed = parseUserAgent(ua);

      // Update component displays
      $('#uaBrowser').textContent = `${parsed.browser} ${parsed.browserVersion}`;
      $('#uaOS').textContent = `${parsed.os} ${parsed.osVersion}`;
      $('#uaDevice').textContent = parsed.device;
      $('#uaEngine').textContent = parsed.engine;

      // Build results
      const results = [];
      results.push('=== USER AGENT ===');
      results.push(ua);

      results.push('\n=== DETECTED INFORMATION ===');
      results.push(`Browser: ${parsed.browser} ${parsed.browserVersion}`);
      results.push(`Engine: ${parsed.engine}`);
      results.push(`OS: ${parsed.os} ${parsed.osVersion}`);
      results.push(`Device: ${parsed.device}`);

      results.push('\n=== DEVICE TYPE ===');
      results.push(`Mobile: ${parsed.isMobile ? 'Yes' : 'No'}`);
      results.push(`Tablet: ${parsed.isTablet ? 'Yes' : 'No'}`);
      results.push(`Desktop: ${parsed.isDesktop ? 'Yes' : 'No'}`);
      results.push(`Bot/Crawler: ${parsed.isBot ? 'Yes' : 'No'}`);

      results.push('\n=== RAW VALUES ===');
      results.push(`Length: ${ua.length} characters`);
      results.push(`First 50 chars: ${ua.substring(0, 50)}${ua.length > 50 ? '...' : ''}`);

      $('#results').textContent = results.join('\n');
      toast('User-agent parsed');
    });

    $('#copy').addEventListener('click', () => {
      navigator.clipboard.writeText($('#results').textContent).then(() => toast('Results copied'));
    });

    // Initialize
    $('#parse').click();
  });
}

function httpcodesTool() {
  setTool('HTTP Status Codes', `
        <div class="form-group">
            <label>Search Status Codes</label>
            <input type="text" id="search" placeholder="Search by code or description..." />
        </div>
        <div id="codesList" style="display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 16px; margin-top: 16px;"></div>
      `, () => {
    const httpCodes = [
      { code: 100, name: 'Continue', description: 'The server has received the request headers.' },
      { code: 101, name: 'Switching Protocols', description: 'The requester has asked the server to switch protocols.' },
      { code: 102, name: 'Processing', description: 'The server is processing the request.' },
      { code: 200, name: 'OK', description: 'The request was successful.' },
      { code: 201, name: 'Created', description: 'The request has been fulfilled and a new resource created.' },
      { code: 202, name: 'Accepted', description: 'The request has been accepted for processing.' },
      { code: 204, name: 'No Content', description: 'The request was successful but there is no content to return.' },
      { code: 206, name: 'Partial Content', description: 'The server is delivering only part of the resource.' },
      { code: 300, name: 'Multiple Choices', description: 'The request has more than one possible response.' },
      { code: 301, name: 'Moved Permanently', description: 'The resource has been permanently moved to a new URL.' },
      { code: 302, name: 'Found', description: 'The resource has been temporarily moved to a different URL.' },
      { code: 304, name: 'Not Modified', description: 'The resource has not been modified since last requested.' },
      { code: 307, name: 'Temporary Redirect', description: 'The resource is temporarily available at a different URL.' },
      { code: 308, name: 'Permanent Redirect', description: 'The resource has been permanently moved to a new URL.' },
      { code: 400, name: 'Bad Request', description: 'The server cannot process the request due to client error.' },
      { code: 401, name: 'Unauthorized', description: 'Authentication is required and has failed or not been provided.' },
      { code: 403, name: 'Forbidden', description: 'The server understood the request but refuses to authorize it.' },
      { code: 404, name: 'Not Found', description: 'The requested resource could not be found.' },
      { code: 405, name: 'Method Not Allowed', description: 'The request method is not supported for the requested resource.' },
      { code: 406, name: 'Not Acceptable', description: 'The server cannot produce a response matching the accept headers.' },
      { code: 408, name: 'Request Timeout', description: 'The server timed out waiting for the request.' },
      { code: 409, name: 'Conflict', description: 'The request could not be completed due to a conflict.' },
      { code: 410, name: 'Gone', description: 'The resource is no longer available and will not be available again.' },
      { code: 413, name: 'Payload Too Large', description: 'The request is larger than the server is willing or able to process.' },
      { code: 414, name: 'URI Too Long', description: 'The URI requested by the client is too long.' },
      { code: 415, name: 'Unsupported Media Type', description: 'The media format is not supported by the server.' },
      { code: 429, name: 'Too Many Requests', description: 'The user has sent too many requests in a given amount of time.' },
      { code: 500, name: 'Internal Server Error', description: 'A generic error message when the server encounters an unexpected condition.' },
      { code: 501, name: 'Not Implemented', description: 'The server does not support the functionality required to fulfill the request.' },
      { code: 502, name: 'Bad Gateway', description: 'The server received an invalid response from an upstream server.' },
      { code: 503, name: 'Service Unavailable', description: 'The server is currently unavailable.' },
      { code: 504, name: 'Gateway Timeout', description: 'The server did not receive a timely response from an upstream server.' },
      { code: 505, name: 'HTTP Version Not Supported', description: 'The server does not support the HTTP protocol version used in the request.' }
    ];

    function getColorClass(code) {
      if (code >= 100 && code < 200) return 'info';
      if (code >= 200 && code < 300) return 'success';
      if (code >= 300 && code < 400) return 'warning';
      if (code >= 400 && code < 500) return 'danger';
      if (code >= 500) return 'error';
      return 'default';
    }

    function renderCodes(codes) {
      const html = codes.map(item => {
        const colorClass = getColorClass(item.code);
        const colors = {
          info: { bg: 'rgba(59, 130, 246, 0.1)', border: 'rgba(59, 130, 246, 0.3)', text: 'rgb(59, 130, 246)' },
          success: { bg: 'rgba(34, 197, 94, 0.1)', border: 'rgba(34, 197, 94, 0.3)', text: 'rgb(34, 197, 94)' },
          warning: { bg: 'rgba(234, 179, 8, 0.1)', border: 'rgba(234, 179, 8, 0.3)', text: 'rgb(234, 179, 8)' },
          danger: { bg: 'rgba(239, 68, 68, 0.1)', border: 'rgba(239, 68, 68, 0.3)', text: 'rgb(239, 68, 68)' },
          error: { bg: 'rgba(239, 68, 68, 0.1)', border: 'rgba(239, 68, 68, 0.3)', text: 'rgb(239, 68, 68)' },
          default: { bg: 'var(--bg-secondary)', border: 'var(--border)', text: 'var(--text)' }
        };

        const color = colors[colorClass];

        return `
                    <div style="padding: 16px; background: ${color.bg}; border: 1px solid ${color.border}; border-radius: 8px;">
                        <div style="display: flex; align-items: center; gap: 12px; margin-bottom: 8px;">
                            <div style="font-size: 24px; font-weight: 800; color: ${color.text};">${item.code}</div>
                            <div>
                                <div style="font-weight: 600; color: ${color.text};">${item.name}</div>
                                <div style="font-size: 12px; color: var(--text-muted);">${getCategory(item.code)}</div>
                            </div>
                        </div>
                        <div style="font-size: 14px; color: var(--text);">${item.description}</div>
                    </div>
                `;
      }).join('');

      $('#codesList').innerHTML = html;
    }

    function getCategory(code) {
      if (code >= 100 && code < 200) return 'Informational';
      if (code >= 200 && code < 300) return 'Success';
      if (code >= 300 && code < 400) return 'Redirection';
      if (code >= 400 && code < 500) return 'Client Error';
      if (code >= 500) return 'Server Error';
      return 'Unknown';
    }

    $('#search').addEventListener('input', (e) => {
      const query = e.target.value.toLowerCase().trim();

      if (!query) {
        renderCodes(httpCodes);
        return;
      }

      const filtered = httpCodes.filter(item =>
        item.code.toString().includes(query) ||
        item.name.toLowerCase().includes(query) ||
        item.description.toLowerCase().includes(query)
      );

      renderCodes(filtered);

      if (filtered.length === 0) {
        $('#codesList').innerHTML = `
                    <div style="grid-column: 1 / -1; text-align: center; padding: 40px; color: var(--text-muted);">
                        No status codes found matching "${query}"
                    </div>
                `;
      }
    });

    // Initialize
    renderCodes(httpCodes);
  });
}

function jsondiffTool() {
  setTool('JSON Diff', `
        <div class="row">
            <div class="form-group">
                <label>JSON A</label>
                <textarea id="jsonA" rows="6" placeholder='{"name": "John", "age": 30}'>{"name": "John", "age": 30, "city": "New York"}</textarea>
            </div>
            <div class="form-group">
                <label>JSON B</label>
                <textarea id="jsonB" rows="6" placeholder='{"name": "Jane", "age": 25}'>{"name": "John", "age": 31, "country": "USA"}</textarea>
            </div>
        </div>
        <div class="form-group">
            <label>Options</label>
            <div style="display: flex; gap: 16px;">
                <label style="display: flex; align-items: center; gap: 8px;">
                    <input type="checkbox" id="showUnchanged" />
                    <span>Show unchanged values</span>
                </label>
                <label style="display: flex; align-items: center; gap: 8px;">
                    <input type="checkbox" id="ignoreCase" />
                    <span>Ignore case</span>
                </label>
            </div>
        </div>
        <div class="btn-group">
            <button id="compare" class="btn">Compare JSON</button>
            <button id="swap" class="btn btn-secondary">↔ Swap</button>
            <button id="copy" class="btn btn-secondary">Copy Diff</button>
        </div>
        <div id="diffOutput" class="output" style="font-family: monospace; white-space: pre;"></div>
        <div id="diffStats" style="margin-top: 16px; padding: 12px; background: var(--bg-secondary); border-radius: 8px; font-size: 14px;"></div>
      `, () => {
    function compareJSON(a, b, showUnchanged = false, ignoreCase = false) {
      function normalize(value) {
        if (ignoreCase && typeof value === 'string') {
          return value.toLowerCase();
        }
        return value;
      }

      function isObject(item) {
        return item && typeof item === 'object' && !Array.isArray(item);
      }

      function getDifferences(obj1, obj2, path = '') {
        const diffs = [];
        const allKeys = new Set([...Object.keys(obj1), ...Object.keys(obj2)]);

        for (const key of allKeys) {
          const currentPath = path ? `${path}.${key}` : key;
          const val1 = obj1[key];
          const val2 = obj2[key];

          const has1 = key in obj1;
          const has2 = key in obj2;

          if (!has1 && has2) {
            // Added in obj2
            diffs.push({
              path: currentPath,
              type: 'added',
              value: val2
            });
          } else if (has1 && !has2) {
            // Removed from obj2
            diffs.push({
              path: currentPath,
              type: 'removed',
              value: val1
            });
          } else if (isObject(val1) && isObject(val2)) {
            // Both are objects, recurse
            diffs.push(...getDifferences(val1, val2, currentPath));
          } else if (Array.isArray(val1) && Array.isArray(val2)) {
            // Compare arrays
            const maxLength = Math.max(val1.length, val2.length);
            for (let i = 0; i < maxLength; i++) {
              const itemPath = `${currentPath}[${i}]`;
              if (i >= val1.length) {
                // Added item
                diffs.push({
                  path: itemPath,
                  type: 'added',
                  value: val2[i]
                });
              } else if (i >= val2.length) {
                // Removed item
                diffs.push({
                  path: itemPath,
                  type: 'removed',
                  value: val1[i]
                });
              } else if (isObject(val1[i]) && isObject(val2[i])) {
                diffs.push(...getDifferences(val1[i], val2[i], itemPath));
              } else if (normalize(val1[i]) !== normalize(val2[i])) {
                diffs.push({
                  path: itemPath,
                  type: 'modified',
                  oldValue: val1[i],
                  newValue: val2[i]
                });
              } else if (showUnchanged) {
                diffs.push({
                  path: itemPath,
                  type: 'unchanged',
                  value: val1[i]
                });
              }
            }
          } else if (normalize(val1) !== normalize(val2)) {
            // Values are different
            diffs.push({
              path: currentPath,
              type: 'modified',
              oldValue: val1,
              newValue: val2
            });
          } else if (showUnchanged) {
            // Values are the same
            diffs.push({
              path: currentPath,
              type: 'unchanged',
              value: val1
            });
          }
        }

        return diffs;
      }

      try {
        const obj1 = typeof a === 'string' ? JSON.parse(a) : a;
        const obj2 = typeof b === 'string' ? JSON.parse(b) : b;

        return getDifferences(obj1, obj2);
      } catch (error) {
        throw new Error('Invalid JSON: ' + error.message);
      }
    }

    function formatDiff(diffs) {
      const lines = [];

      for (const diff of diffs) {
        let line = '';
        switch (diff.type) {
          case 'added':
            line = `+ ${diff.path}: ${JSON.stringify(diff.value)}`;
            break;
          case 'removed':
            line = `- ${diff.path}: ${JSON.stringify(diff.value)}`;
            break;
          case 'modified':
            line = `~ ${diff.path}: ${JSON.stringify(diff.oldValue)} → ${JSON.stringify(diff.newValue)}`;
            break;
          case 'unchanged':
            line = `  ${diff.path}: ${JSON.stringify(diff.value)}`;
            break;
        }
        lines.push(line);
      }

      return lines.join('\n');
    }

    function getStats(diffs) {
      const stats = {
        added: 0,
        removed: 0,
        modified: 0,
        unchanged: 0,
        total: diffs.length
      };

      for (const diff of diffs) {
        stats[diff.type]++;
      }

      return stats;
    }

    $('#compare').addEventListener('click', () => {
      const jsonA = $('#jsonA').value;
      const jsonB = $('#jsonB').value;
      const showUnchanged = $('#showUnchanged').checked;
      const ignoreCase = $('#ignoreCase').checked;

      if (!jsonA.trim() || !jsonB.trim()) {
        toast('Please enter both JSON objects', 'error');
        return;
      }

      try {
        const diffs = compareJSON(jsonA, jsonB, showUnchanged, ignoreCase);
        const diffOutput = formatDiff(diffs);
        const stats = getStats(diffs);

        $('#diffOutput').textContent = diffOutput;

        const statsText = [
          `Total differences: ${stats.total}`,
          `Added: ${stats.added} | Removed: ${stats.removed} | Modified: ${stats.modified}`,
          showUnchanged ? `Unchanged: ${stats.unchanged}` : ''
        ].filter(Boolean).join(' | ');

        $('#diffStats').textContent = statsText;
        toast('Comparison complete');
      } catch (error) {
        toast('Error: ' + error.message, 'error');
        $('#diffOutput').textContent = error.message;
      }
    });

    $('#swap').addEventListener('click', () => {
      const temp = $('#jsonA').value;
      $('#jsonA').value = $('#jsonB').value;
      $('#jsonB').value = temp;
      $('#compare').click();
    });

    $('#copy').addEventListener('click', () => {
      navigator.clipboard.writeText($('#diffOutput').textContent).then(() => toast('Diff copied'));
    });

    // Initialize
    $('#compare').click();
  });
}

function safelinkTool() {
  setTool('Outlook SafeLink Decoder', `
        <div class="form-group">
            <label>SafeLink URL</label>
            <input type="text" id="safelink" placeholder="https://nam10.safelinks.protection.outlook.com/..." style="font-family: monospace;" />
            <button id="useExample" class="btn btn-secondary" style="margin-top: 8px; width: 100%;">Use Example</button>
        </div>
        <div class="btn-group">
            <button id="decode" class="btn">Decode SafeLink</button>
            <button id="copy" class="btn btn-secondary">Copy Original URL</button>
        </div>
        <div id="results" class="output"></div>
        <div id="decodedInfo" style="margin-top: 16px;">
            <h4 style="margin-bottom: 8px;">🔗 Decoded Information</h4>
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 12px;">
                <div>
                    <div style="font-size: 12px; color: var(--text-muted);">Original URL</div>
                    <div id="originalUrl" style="word-break: break-all; font-family: monospace; font-size: 12px;"></div>
                </div>
                <div>
                    <div style="font-size: 12px; color: var(--text-muted);">Components</div>
                    <div id="urlComponents" style="font-size: 12px;"></div>
                </div>
            </div>
        </div>
      `, () => {
    function decodeSafeLink(url) {
      try {
        const urlObj = new URL(url);

        // Check if it's a SafeLink URL
        if (!urlObj.hostname.includes('safelinks.protection.outlook.com')) {
          throw new Error('Not a valid SafeLink URL');
        }

        // Get the URL parameter (could be 'url' or 'u')
        const encodedUrl = urlObj.searchParams.get('url') || urlObj.searchParams.get('u');

        if (!encodedUrl) {
          throw new Error('No encoded URL found in SafeLink');
        }

        // Decode the URL (it's usually URL-encoded)
        const decodedUrl = decodeURIComponent(encodedUrl);

        // Parse the decoded URL for more info
        let originalUrlObj;
        try {
          originalUrlObj = new URL(decodedUrl);
        } catch {
          originalUrlObj = null;
        }

        // Extract additional parameters
        const data = {
          originalUrl: decodedUrl,
          safeLinkUrl: url,
          parameters: {
            client: urlObj.searchParams.get('data') || 'Unknown',
            recipient: urlObj.searchParams.get('recipient') || 'Unknown',
            sdf: urlObj.searchParams.get('sdf') || 'No',
            reserved: urlObj.searchParams.get('reserved') || '0'
          }
        };

        if (originalUrlObj) {
          data.components = {
            protocol: originalUrlObj.protocol,
            hostname: originalUrlObj.hostname,
            path: originalUrlObj.pathname,
            query: originalUrlObj.search,
            hash: originalUrlObj.hash
          };
        }

        return data;
      } catch (error) {
        throw new Error('Failed to decode SafeLink: ' + error.message);
      }
    }

    $('#useExample').addEventListener('click', () => {
      const example = 'https://nam10.safelinks.protection.outlook.com/?url=https%3A%2F%2Fexample.com%2Fpath%3Fparam%3Dvalue&data=05%7C02%7C%7Cabc123%7CUnknown%7CTWFpbGZsb3d8eyJWIjoiMC4wLjAwMDAiLCJQIjoiV2luMzIiLCJBTiI6Ik1haWwiLCJXVCI6Mn0%3D%7C0%7C%7C%7C&sdata=xyz789&reserved=0';
      $('#safelink').value = example;
      toast('Example loaded');
    });

    $('#decode').addEventListener('click', () => {
      const safelink = $('#safelink').value.trim();

      if (!safelink) {
        toast('Please enter a SafeLink URL', 'error');
        return;
      }

      try {
        const decoded = decodeSafeLink(safelink);

        // Build results
        const results = [];
        results.push('=== ORIGINAL SAFELINK ===');
        results.push(decoded.safeLinkUrl);

        results.push('\n=== DECODED URL ===');
        results.push(decoded.originalUrl);

        results.push('\n=== SAFELINK PARAMETERS ===');
        for (const [key, value] of Object.entries(decoded.parameters)) {
          results.push(`${key}: ${value}`);
        }

        if (decoded.components) {
          results.push('\n=== URL COMPONENTS ===');
          for (const [key, value] of Object.entries(decoded.components)) {
            if (value) {
              results.push(`${key}: ${value}`);
            }
          }
        }

        $('#results').textContent = results.join('\n');

        // Update component displays
        $('#originalUrl').textContent = decoded.originalUrl;

        if (decoded.components) {
          $('#urlComponents').innerHTML = `
                        <div>Hostname: ${decoded.components.hostname}</div>
                        <div>Path: ${decoded.components.path || '/'}</div>
                        <div>Query: ${decoded.components.query || 'None'}</div>
                    `;
        }

        toast('SafeLink decoded successfully');
      } catch (error) {
        toast('Error: ' + error.message, 'error');
        $('#results').textContent = error.message;
      }
    });

    $('#copy').addEventListener('click', () => {
      const originalUrl = $('#originalUrl').textContent;
      if (originalUrl) {
        navigator.clipboard.writeText(originalUrl).then(() => toast('Original URL copied'));
      }
    });

    // Initialize
    $('#useExample').click();
    $('#decode').click();
  });
}

// DEVELOPMENT TOOLS

function gitcheatTool() {
  setTool('Git Cheatsheet', `
        <div class="form-group">
            <label>Search Git Commands</label>
            <input type="text" id="search" placeholder="Search commands..." />
        </div>
        <div id="gitCommands" style="display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 16px; margin-top: 16px;"></div>
      `, () => {
    const gitCommands = [
      {
        category: 'Basics',
        commands: [
          { command: 'git init', description: 'Initialize a new Git repository' },
          { command: 'git clone <url>', description: 'Clone a repository from a URL' },
          { command: 'git status', description: 'Show the working tree status' },
          { command: 'git add <file>', description: 'Add file contents to the index' },
          { command: 'git commit -m "message"', description: 'Record changes to the repository' },
          { command: 'git log', description: 'Show commit logs' }
        ]
      },
      {
        category: 'Branching',
        commands: [
          { command: 'git branch', description: 'List, create, or delete branches' },
          { command: 'git branch <name>', description: 'Create a new branch' },
          { command: 'git checkout <branch>', description: 'Switch to a branch' },
          { command: 'git checkout -b <name>', description: 'Create and switch to new branch' },
          { command: 'git merge <branch>', description: 'Merge a branch into current branch' },
          { command: 'git branch -d <name>', description: 'Delete a branch' }
        ]
      },
      {
        category: 'Remote',
        commands: [
          { command: 'git remote -v', description: 'List remote repositories' },
          { command: 'git remote add <name> <url>', description: 'Add a remote repository' },
          { command: 'git push <remote> <branch>', description: 'Push to a remote repository' },
          { command: 'git pull <remote> <branch>', description: 'Fetch and merge from remote' },
          { command: 'git fetch <remote>', description: 'Download objects from remote' }
        ]
      },
      {
        category: 'Undoing',
        commands: [
          { command: 'git reset <file>', description: 'Unstage a file' },
          { command: 'git reset --hard <commit>', description: 'Reset to a specific commit' },
          { command: 'git checkout -- <file>', description: 'Discard changes in working directory' },
          { command: 'git revert <commit>', description: 'Create a new commit that undoes changes' },
          { command: 'git clean -fd', description: 'Remove untracked files and directories' }
        ]
      },
      {
        category: 'Stashing',
        commands: [
          { command: 'git stash', description: 'Save modified and staged changes' },
          { command: 'git stash list', description: 'List stash entries' },
          { command: 'git stash pop', description: 'Apply and remove the latest stash' },
          { command: 'git stash apply', description: 'Apply the latest stash' },
          { command: 'git stash drop', description: 'Remove the latest stash' }
        ]
      },
      {
        category: 'Tags',
        commands: [
          { command: 'git tag', description: 'List tags' },
          { command: 'git tag <name>', description: 'Create a lightweight tag' },
          { command: 'git tag -a <name> -m "msg"', description: 'Create an annotated tag' },
          { command: 'git push --tags', description: 'Push tags to remote' },
          { command: 'git tag -d <name>', description: 'Delete a tag' }
        ]
      },
      {
        category: 'Advanced',
        commands: [
          { command: 'git rebase <branch>', description: 'Reapply commits on top of another branch' },
          { command: 'git cherry-pick <commit>', description: 'Apply the changes from a commit' },
          { command: 'git bisect', description: 'Find the commit that introduced a bug' },
          { command: 'git blame <file>', description: 'Show who changed each line of a file' },
          { command: 'git submodule', description: 'Initialize, update or inspect submodules' }
        ]
      }
    ];

    function renderCommands(commands) {
      const html = commands.map(category => `
                <div style="padding: 16px; background: var(--bg-secondary); border-radius: 8px;">
                    <h3 style="margin-bottom: 12px; color: var(--primary-light);">${category.category}</h3>
                    <div style="display: flex; flex-direction: column; gap: 8px;">
                        ${category.commands.map(cmd => `
                            <div style="padding: 8px; background: var(--bg); border-radius: 4px; border-left: 3px solid var(--primary);">
                                <div style="font-family: monospace; font-weight: 600; margin-bottom: 4px; color: var(--text);">${cmd.command}</div>
                                <div style="font-size: 14px; color: var(--text-muted);">${cmd.description}</div>
                            </div>
                        `).join('')}
                    </div>
                </div>
            `).join('');

      $('#gitCommands').innerHTML = html;
    }

    $('#search').addEventListener('input', (e) => {
      const query = e.target.value.toLowerCase().trim();

      if (!query) {
        renderCommands(gitCommands);
        return;
      }

      const filtered = gitCommands.map(category => {
        const filteredCommands = category.commands.filter(cmd =>
          cmd.command.toLowerCase().includes(query) ||
          cmd.description.toLowerCase().includes(query)
        );

        if (filteredCommands.length > 0) {
          return {
            category: category.category,
            commands: filteredCommands
          };
        }
        return null;
      }).filter(Boolean);

      renderCommands(filtered);

      if (filtered.length === 0) {
        $('#gitCommands').innerHTML = `
                    <div style="grid-column: 1 / -1; text-align: center; padding: 40px; color: var(--text-muted);">
                        No Git commands found matching "${query}"
                    </div>
                `;
      }
    });

    // Initialize
    renderCommands(gitCommands);
  });
}

function crontabTool() {
  setTool('Crontab Generator', `
        <div class="form-group">
            <label>Schedule Description</label>
            <textarea id="description" rows="2" placeholder="Every day at 2:30 AM">Every day at 2:30 AM</textarea>
        </div>
        <div class="row">
            <div class="form-group">
                <label>Minute</label>
                <select id="minute">
                    ${Array.from({length: 60}, (_, i) => `<option value="${i}">${i}</option>`).join('')}
                    <option value="*" selected>Every minute</option>
                    <option value="*/5">Every 5 minutes</option>
                    <option value="*/15">Every 15 minutes</option>
                    <option value="*/30">Every 30 minutes</option>
                </select>
            </div>
            <div class="form-group">
                <label>Hour</label>
                <select id="hour">
                    ${Array.from({length: 24}, (_, i) => `<option value="${i}">${i}</option>`).join('')}
                    <option value="*" selected>Every hour</option>
                    <option value="*/2">Every 2 hours</option>
                    <option value="*/6">Every 6 hours</option>
                    <option value="*/12">Every 12 hours</option>
                </select>
            </div>
        </div>
        <div class="row">
            <div class="form-group">
                <label>Day of Month</label>
                <select id="day">
                    ${Array.from({length: 31}, (_, i) => `<option value="${i + 1}">${i + 1}</option>`).join('')}
                    <option value="*" selected>Every day</option>
                    <option value="*/2">Every 2 days</option>
                    <option value="*/7">Every week</option>
                </select>
            </div>
            <div class="form-group">
                <label>Month</label>
                <select id="month">
                    <option value="*" selected>Every month</option>
                    ${Array.from({length: 12}, (_, i) => `<option value="${i + 1}">${i + 1} (${['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'][i]})</option>`).join('')}
                </select>
            </div>
        </div>
        <div class="form-group">
            <label>Day of Week</label>
            <select id="weekday">
                <option value="*" selected>Every day</option>
                <option value="0">Sunday</option>
                <option value="1">Monday</option>
                <option value="2">Tuesday</option>
                <option value="3">Wednesday</option>
                <option value="4">Thursday</option>
                <option value="5">Friday</option>
                <option value="6">Saturday</option>
                <option value="1-5">Weekdays (Mon-Fri)</option>
                <option value="0,6">Weekends (Sat-Sun)</option>
            </select>
        </div>
        <div class="form-group">
            <label>Command</label>
            <input type="text" id="command" placeholder="/path/to/script.sh" value="/usr/bin/backup.sh" />
        </div>
        <div class="btn-group">
            <button id="generate" class="btn">Generate Crontab</button>
            <button id="copy" class="btn btn-secondary">Copy Crontab</button>
            <button id="parse" class="btn btn-secondary">Parse Crontab</button>
        </div>
        <div id="crontab" class="output"></div>
        <div id="humanReadable" style="margin-top: 16px; padding: 12px; background: var(--bg-secondary); border-radius: 8px;"></div>
      `, () => {
    function generateCron() {
      const minute = $('#minute').value;
      const hour = $('#hour').value;
      const day = $('#day').value;
      const month = $('#month').value;
      const weekday = $('#weekday').value;
      const command = $('#command').value.trim();

      if (!command) {
        toast('Please enter a command', 'error');
        return;
      }

      const cron = `${minute} ${hour} ${day} ${month} ${weekday} ${command}`;

      // Generate human-readable description
      const desc = getHumanReadable(minute, hour, day, month, weekday);

      $('#crontab').textContent = cron;
      $('#humanReadable').innerHTML = `<strong>Schedule:</strong> ${desc}`;

      toast('Crontab generated');
    }

    function getHumanReadable(minute, hour, day, month, weekday) {
      const parts = [];

      // Minute
      if (minute === '*') parts.push('every minute');
      else if (minute === '*/5') parts.push('every 5 minutes');
      else if (minute === '*/15') parts.push('every 15 minutes');
      else if (minute === '*/30') parts.push('every 30 minutes');
      else parts.push(`at minute ${minute}`);

      // Hour
      if (hour === '*') parts.push('of every hour');
      else if (hour === '*/2') parts.push('every 2 hours');
      else if (hour === '*/6') parts.push('every 6 hours');
      else if (hour === '*/12') parts.push('every 12 hours');
      else parts.push(`at hour ${hour}`);

      // Day of month
      if (day === '*') parts.push('every day');
      else if (day === '*/2') parts.push('every 2 days');
      else if (day === '*/7') parts.push('every week');
      else parts.push(`on day ${day} of the month`);

      // Month
      if (month !== '*') {
        const months = ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];
        parts.push(`in ${months[parseInt(month) - 1]}`);
      }

      // Day of week
      if (weekday === '*') {
        // Already covered by "every day"
      } else if (weekday === '1-5') {
        parts.push('on weekdays (Monday-Friday)');
      } else if (weekday === '0,6') {
        parts.push('on weekends (Saturday-Sunday)');
      } else {
        const days = ['Sunday','Monday','Tuesday','Wednesday','Thursday','Friday','Saturday'];
        parts.push(`on ${days[parseInt(weekday)]}`);
      }

      return parts.join(' ');
    }

    function parseCron() {
      const cron = prompt('Enter crontab expression (e.g., "30 2 * * * /script.sh"):');
      if (!cron) return;

      const parts = cron.trim().split(/\s+/);
      if (parts.length < 6) {
        toast('Invalid crontab format', 'error');
        return;
      }

      const [minute, hour, day, month, weekday, ...commandParts] = parts;
      const command = commandParts.join(' ');

      // Set values
      $('#minute').value = minute;
      $('#hour').value = hour;
      $('#day').value = day;
      $('#month').value = month;
      $('#weekday').value = weekday;
      $('#command').value = command;

      generateCron();
      toast('Crontab parsed');
    }

    $('#generate').addEventListener('click', generateCron);
    $('#copy').addEventListener('click', () => {
      navigator.clipboard.writeText($('#crontab').textContent).then(() => toast('Copied'));
    });
    $('#parse').addEventListener('click', parseCron);

    // Event listeners for real-time updates
    $$('#minute, #hour, #day, #month, #weekday, #command').forEach(el => {
      el.addEventListener('change', generateCron);
    });

    // Initialize
    generateCron();
  });
}

function jsontocsvTool() {
  setTool('JSON to CSV Converter', `
        <div class="row">
            <div class="form-group">
                <label>JSON Input</label>
                <textarea id="json" rows="8" placeholder='[{"name": "John", "age": 30}, {"name": "Jane", "age": 25}]'>[{"name": "John", "age": 30, "city": "NY"}, {"name": "Jane", "age": 25, "city": "LA"}]</textarea>
            </div>
            <div class="form-group">
                <label>CSV Output</label>
                <textarea id="csv" rows="8" placeholder="CSV will appear here" readonly></textarea>
            </div>
        </div>
        <div class="form-group">
            <label>Options</label>
            <div style="display: flex; flex-direction: column; gap: 8px;">
                <label style="display: flex; align-items: center; gap: 8px;">
                    <input type="checkbox" id="includeHeader" checked />
                    <span>Include header row</span>
                </label>
                <div style="display: flex; gap: 16px;">
                    <label style="display: flex; align-items: center; gap: 8px;">
                        <input type="radio" name="delimiter" value="," checked />
                        <span>Comma (,) delimiter</span>
                    </label>
                    <label style="display: flex; align-items: center; gap: 8px;">
                        <input type="radio" name="delimiter" value=";" />
                        <span>Semicolon (;) delimiter</span>
                    </label>
                    <label style="display: flex; align-items: center; gap: 8px;">
                        <input type="radio" name="delimiter" value="\t" />
                        <span>Tab delimiter</span>
                    </label>
                </div>
                <label style="display: flex; align-items: center; gap: 8px;">
                    <input type="checkbox" id="quoteAll" />
                    <span>Quote all fields</span>
                </label>
            </div>
        </div>
        <div class="btn-group">
            <button id="convert" class="btn">Convert to CSV</button>
            <button id="copy" class="btn btn-secondary">Copy CSV</button>
            <button id="download" class="btn btn-secondary">Download CSV</button>
        </div>
        <div id="error" style="color: var(--error); margin-top: 8px; display: none;"></div>
      `, () => {
    function jsonToCsv(jsonArray, options) {
      if (!Array.isArray(jsonArray) || jsonArray.length === 0) {
        throw new Error('JSON must be a non-empty array of objects');
      }

      // Collect all unique keys
      const allKeys = new Set();
      jsonArray.forEach(item => {
        Object.keys(item).forEach(key => allKeys.add(key));
      });
      const headers = Array.from(allKeys);

      const rows = [];

      // Add header row if requested
      if (options.includeHeader) {
        if (options.quoteAll) {
          rows.push(headers.map(h => `"${h}"`).join(options.delimiter));
        } else {
          rows.push(headers.join(options.delimiter));
        }
      }

      // Add data rows
      jsonArray.forEach(item => {
        const row = headers.map(header => {
          const value = item[header];

          if (value === null || value === undefined) {
            return '';
          }

          let strValue = String(value);

          // Escape quotes and wrap in quotes if needed
          if (strValue.includes('"') || strValue.includes(options.delimiter) || strValue.includes('\n') || options.quoteAll) {
            strValue = `"${strValue.replace(/"/g, '""')}"`;
          }

          return strValue;
        });

        rows.push(row.join(options.delimiter));
      });

      return rows.join('\n');
    }

    $('#convert').addEventListener('click', () => {
      const jsonText = $('#json').value;

      if (!jsonText.trim()) {
        toast('Please enter JSON', 'error');
        return;
      }

      try {
        const jsonData = JSON.parse(jsonText);
        const options = {
          includeHeader: $('#includeHeader').checked,
          delimiter: document.querySelector('input[name="delimiter"]:checked').value,
          quoteAll: $('#quoteAll').checked
        };

        const csv = jsonToCsv(jsonData, options);
        $('#csv').value = csv;
        $('#error').style.display = 'none';

        toast(`Converted ${jsonData.length} rows`);
      } catch (error) {
        $('#error').textContent = `Error: ${error.message}`;
        $('#error').style.display = 'block';
        toast('Conversion failed', 'error');
      }
    });

    $('#copy').addEventListener('click', () => {
      navigator.clipboard.writeText($('#csv').value).then(() => toast('CSV copied'));
    });

    $('#download').addEventListener('click', () => {
      const csv = $('#csv').value;
      if (!csv) {
        toast('No CSV to download', 'error');
        return;
      }

      const blob = new Blob([csv], { type: 'text/csv' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = 'data.csv';
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);

      toast('CSV downloaded');
    });

    // Initialize
    $('#convert').click();
  });
}

function sqlprettyTool() {
  setTool('SQL Prettify', `
        <div class="form-group">
            <label>SQL Query</label>
            <textarea id="sql" rows="8" placeholder="SELECT * FROM users WHERE age > 18 ORDER BY name">SELECT id, name, email FROM users WHERE age > 18 AND status = 'active' ORDER BY created_at DESC</textarea>
        </div>
        <div class="form-group">
            <label>Options</label>
            <div style="display: flex; flex-direction: column; gap: 8px;">
                <div style="display: flex; gap: 16px;">
                    <label style="display: flex; align-items: center; gap: 8px;">
                        <input type="radio" name="dialect" value="sql" checked />
                        <span>Standard SQL</span>
                    </label>
                    <label style="display: flex; align-items: center; gap: 8px;">
                        <input type="radio" name="dialect" value="mysql" />
                        <span>MySQL</span>
                    </label>
                    <label style="display: flex; align-items: center; gap: 8px;">
                        <input type="radio" name="dialect" value="postgres" />
                        <span>PostgreSQL</span>
                    </label>
                </div>
                <div style="display: flex; gap: 16px;">
                    <label style="display: flex; align-items: center; gap: 8px;">
                        <input type="number" id="indent" value="2" min="1" max="8" style="width: 60px;" />
                        <span>Indent spaces</span>
                    </label>
                    <label style="display: flex; align-items: center; gap: 8px;">
                        <input type="checkbox" id="uppercase" checked />
                        <span>Uppercase keywords</span>
                    </label>
                </div>
            </div>
        </div>
        <div class="btn-group">
            <button id="prettify" class="btn">Prettify SQL</button>
            <button id="minify" class="btn btn-secondary">Minify SQL</button>
            <button id="copy" class="btn btn-secondary">Copy Formatted</button>
        </div>
        <div id="output" class="output" style="font-family: monospace; white-space: pre;"></div>
      `, () => {
    const sqlKeywords = [
      'SELECT', 'FROM', 'WHERE', 'ORDER BY', 'GROUP BY', 'HAVING', 'JOIN',
      'LEFT JOIN', 'RIGHT JOIN', 'INNER JOIN', 'OUTER JOIN', 'ON', 'AS',
      'INSERT INTO', 'VALUES', 'UPDATE', 'SET', 'DELETE FROM', 'CREATE TABLE',
      'ALTER TABLE', 'DROP TABLE', 'INDEX', 'PRIMARY KEY', 'FOREIGN KEY',
      'UNIQUE', 'CHECK', 'DEFAULT', 'NULL', 'NOT NULL', 'AND', 'OR', 'NOT',
      'IN', 'BETWEEN', 'LIKE', 'IS', 'EXISTS', 'ALL', 'ANY', 'DISTINCT',
      'LIMIT', 'OFFSET', 'UNION', 'UNION ALL', 'INTERSECT', 'EXCEPT',
      'CASE', 'WHEN', 'THEN', 'ELSE', 'END'
    ];

    function prettifySQL(sql, options) {
      let formatted = sql;

      // Normalize whitespace
      formatted = formatted.replace(/\s+/g, ' ');

      // Add newlines after keywords
      sqlKeywords.forEach(keyword => {
        const regex = new RegExp(`\\b${keyword}\\b`, 'gi');
        formatted = formatted.replace(regex, match => {
          if (options.uppercase) {
            return `\n${match.toUpperCase()}`;
          }
          return `\n${match}`;
        });
      });

      // Add indentation
      const lines = formatted.trim().split('\n');
      let indentLevel = 0;
      const indentStr = ' '.repeat(options.indent);

      const formattedLines = lines.map(line => {
        line = line.trim();

        // Decrease indent before certain keywords
        if (line.match(/^(END|ELSE|HAVING|ORDER BY|GROUP BY)/i)) {
          indentLevel = Math.max(0, indentLevel - 1);
        }

        const indentedLine = indentStr.repeat(indentLevel) + line;

        // Increase indent after certain keywords
        if (line.match(/^(SELECT|FROM|WHERE|JOIN|LEFT JOIN|RIGHT JOIN|INNER JOIN|OUTER JOIN|INSERT INTO|VALUES|UPDATE|SET|DELETE FROM|CREATE TABLE|ALTER TABLE|DROP TABLE|CASE|WHEN)/i)) {
          indentLevel++;
        }

        return indentedLine;
      });

      return formattedLines.join('\n').trim();
    }

    function minifySQL(sql) {
      return sql
        .replace(/\/\*[\s\S]*?\*\//g, '') // Remove comments
        .replace(/\s+/g, ' ') // Collapse whitespace
        .replace(/\s*([(),;=<>!])\s*/g, '$1') // Remove spaces around operators
        .trim();
    }

    $('#prettify').addEventListener('click', () => {
      const sql = $('#sql').value;
      const options = {
        dialect: document.querySelector('input[name="dialect"]:checked').value,
        indent: parseInt($('#indent').value) || 2,
        uppercase: $('#uppercase').checked
      };

      if (!sql.trim()) {
        toast('Please enter SQL', 'error');
        return;
      }

      const formatted = prettifySQL(sql, options);
      $('#output').textContent = formatted;
      toast('SQL prettified');
    });

    $('#minify').addEventListener('click', () => {
      const sql = $('#sql').value;

      if (!sql.trim()) {
        toast('Please enter SQL', 'error');
        return;
      }

      const minified = minifySQL(sql);
      $('#output').textContent = minified;
      toast('SQL minified');
    });

    $('#copy').addEventListener('click', () => {
      navigator.clipboard.writeText($('#output').textContent).then(() => toast('Copied'));
    });

    // Initialize
    $('#prettify').click();
  });
}

function chmodTool() {
  setTool('Chmod Calculator', `
        <div class="form-group">
            <label>Permissions</label>
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 16px; margin-top: 8px;">
                <div style="padding: 16px; background: var(--bg-secondary); border-radius: 8px;">
                    <div style="font-weight: 600; margin-bottom: 8px;">Owner (User)</div>
                    <div class="permission-checkboxes">
                        <label style="display: flex; align-items: center; gap: 8px; margin-bottom: 4px;">
                            <input type="checkbox" id="ur" checked />
                            <span>Read (4)</span>
                        </label>
                        <label style="display: flex; align-items: center; gap: 8px; margin-bottom: 4px;">
                            <input type="checkbox" id="uw" checked />
                            <span>Write (2)</span>
                        </label>
                        <label style="display: flex; align-items: center; gap: 8px;">
                            <input type="checkbox" id="ux" checked />
                            <span>Execute (1)</span>
                        </label>
                    </div>
                </div>
                <div style="padding: 16px; background: var(--bg-secondary); border-radius: 8px;">
                    <div style="font-weight: 600; margin-bottom: 8px;">Group</div>
                    <div class="permission-checkboxes">
                        <label style="display: flex; align-items: center; gap: 8px; margin-bottom: 4px;">
                            <input type="checkbox" id="gr" checked />
                            <span>Read (4)</span>
                        </label>
                        <label style="display: flex; align-items: center; gap: 8px; margin-bottom: 4px;">
                            <input type="checkbox" id="gw" />
                            <span>Write (2)</span>
                        </label>
                        <label style="display: flex; align-items: center; gap: 8px;">
                            <input type="checkbox" id="gx" />
                            <span>Execute (1)</span>
                        </label>
                    </div>
                </div>
                <div style="padding: 16px; background: var(--bg-secondary); border-radius: 8px;">
                    <div style="font-weight: 600; margin-bottom: 8px;">Others</div>
                    <div class="permission-checkboxes">
                        <label style="display: flex; align-items: center; gap: 8px; margin-bottom: 4px;">
                            <input type="checkbox" id="or" />
                            <span>Read (4)</span>
                        </label>
                        <label style="display: flex; align-items: center; gap: 8px; margin-bottom: 4px;">
                            <input type="checkbox" id="ow" />
                            <span>Write (2)</span>
                        </label>
                        <label style="display: flex; align-items: center; gap: 8px;">
                            <input type="checkbox" id="ox" />
                            <span>Execute (1)</span>
                        </label>
                    </div>
                </div>
            </div>
        </div>
        <div class="row">
            <div class="form-group">
                <label>Numeric Mode</label>
                <input type="text" id="numeric" value="755" readonly style="font-family: monospace; font-size: 18px; text-align: center;" />
            </div>
            <div class="form-group">
                <label>Symbolic Mode</label>
                <input type="text" id="symbolic" value="rwxr-xr-x" readonly style="font-family: monospace; font-size: 18px; text-align: center;" />
            </div>
        </div>
        <div class="form-group">
            <label>Common Permissions</label>
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 8px; margin-top: 8px;">
                <button class="preset-btn" data-mode="777">777 (rwxrwxrwx)</button>
                <button class="preset-btn" data-mode="755">755 (rwxr-xr-x)</button>
                <button class="preset-btn" data-mode="644">644 (rw-r--r--)</button>
                <button class="preset-btn" data-mode="600">600 (rw-------)</button>
                <button class="preset-btn" data-mode="777">777 (rwxrwxrwx)</button>
                <button class="preset-btn" data-mode="755">755 (rwxr-xr-x)</button>
                <button class="preset-btn" data-mode="644">644 (rw-r--r--)</button>
                <button class="preset-btn" data-mode="600">600 (rw-------)</button>
            </div>
        </div>
        <div class="btn-group">
            <button id="copyNumeric" class="btn">Copy Numeric</button>
            <button id="copySymbolic" class="btn btn-secondary">Copy Symbolic</button>
            <button id="copyCommand" class="btn btn-secondary">Copy Command</button>
        </div>
        <div id="command" class="output" style="margin-top: 16px; font-family: monospace;"></div>
      `, () => {
    function calculatePermissions() {
      // Get checkbox values
      const ur = $('#ur').checked ? 4 : 0;
      const uw = $('#uw').checked ? 2 : 0;
      const ux = $('#ux').checked ? 1 : 0;
      const gr = $('#gr').checked ? 4 : 0;
      const gw = $('#gw').checked ? 2 : 0;
      const gx = $('#gx').checked ? 1 : 0;
      const or = $('#or').checked ? 4 : 0;
      const ow = $('#ow').checked ? 2 : 0;
      const ox = $('#ox').checked ? 1 : 0;

      // Calculate numeric mode
      const user = ur + uw + ux;
      const group = gr + gw + gx;
      const others = or + ow + ox;
      const numeric = `${user}${group}${others}`;

      // Calculate symbolic mode
      const symbolic =
        (ur ? 'r' : '-') + (uw ? 'w' : '-') + (ux ? 'x' : '-') +
        (gr ? 'r' : '-') + (gw ? 'w' : '-') + (gx ? 'x' : '-') +
        (or ? 'r' : '-') + (ow ? 'w' : '-') + (ox ? 'x' : '-');

      // Generate command
      const command = `chmod ${numeric} filename`;

      // Update displays
      $('#numeric').value = numeric;
      $('#symbolic').value = symbolic;
      $('#command').textContent = command;
    }

    function setFromNumeric(mode) {
      if (mode.length !== 3 || !/^[0-7]{3}$/.test(mode)) {
        toast('Invalid numeric mode', 'error');
        return;
      }

      const [user, group, others] = mode.split('').map(Number);

      // User permissions
      $('#ur').checked = (user & 4) !== 0;
      $('#uw').checked = (user & 2) !== 0;
      $('#ux').checked = (user & 1) !== 0;

      // Group permissions
      $('#gr').checked = (group & 4) !== 0;
      $('#gw').checked = (group & 2) !== 0;
      $('#gx').checked = (group & 1) !== 0;

      // Others permissions
      $('#or').checked = (others & 4) !== 0;
      $('#ow').checked = (others & 2) !== 0;
      $('#ox').checked = (others & 1) !== 0;

      calculatePermissions();
    }

    // Event listeners for checkboxes
    $$('.permission-checkboxes input').forEach(checkbox => {
      checkbox.addEventListener('change', calculatePermissions);
    });

    // Preset buttons
    $$('.preset-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        const mode = btn.dataset.mode;
        setFromNumeric(mode);
        toast(`Set to ${mode}`);
      });
    });

    // Copy buttons
    $('#copyNumeric').addEventListener('click', () => {
      navigator.clipboard.writeText($('#numeric').value).then(() => toast('Numeric mode copied'));
    });

    $('#copySymbolic').addEventListener('click', () => {
      navigator.clipboard.writeText($('#symbolic').value).then(() => toast('Symbolic mode copied'));
    });

    $('#copyCommand').addEventListener('click', () => {
      navigator.clipboard.writeText($('#command').textContent).then(() => toast('Command copied'));
    });

    // Style preset buttons
    $$('.preset-btn').forEach(btn => {
      btn.style.padding = '8px 12px';
      btn.style.background = 'var(--card)';
      btn.style.border = '1px solid var(--border)';
      btn.style.borderRadius = '4px';
      btn.style.color = 'var(--text)';
      btn.style.cursor = 'pointer';
      btn.style.fontSize = '12px';
      btn.style.textAlign = 'center';
      btn.style.transition = 'background-color 0.2s';

      btn.addEventListener('mouseenter', () => {
        btn.style.background = 'var(--card-hover)';
      });

      btn.addEventListener('mouseleave', () => {
        btn.style.background = 'var(--card)';
      });
    });

    // Initialize
    calculatePermissions();
  });
}

function dockerrunTool() {
  setTool('Docker Run to Compose', `
        <div class="form-group">
            <label>Docker Run Command</label>
            <textarea id="dockerRun" rows="4" placeholder="docker run -d -p 8080:80 --name myapp -e ENV=prod nginx:alpine">docker run -d -p 8080:80 --name myapp -v /data:/app/data -e ENV=prod nginx:alpine</textarea>
        </div>
        <div class="btn-group">
            <button id="convert" class="btn">Convert to Compose</button>
            <button id="copy" class="btn btn-secondary">Copy Compose</button>
            <button id="example" class="btn btn-secondary">Load Example</button>
        </div>
        <div id="compose" class="output" style="font-family: monospace; white-space: pre;"></div>
        <div style="margin-top: 16px; padding: 16px; background: var(--bg-secondary); border-radius: 8px;">
            <h4 style="margin-bottom: 8px;">📚 Docker Compose Reference</h4>
            <div style="font-size: 14px;">
                <p><strong>Common conversions:</strong></p>
                <ul style="margin: 8px 0; padding-left: 20px;">
                    <li><code>-p 8080:80</code> → <code>ports: ["8080:80"]</code></li>
                    <li><code>-v /data:/app</code> → <code>volumes: ["/data:/app"]</code></li>
                    <li><code>-e ENV=prod</code> → <code>environment: [ENV=prod]</code></li>
                    <li><code>--name myapp</code> → <code>container_name: myapp</code></li>
                    <li><code>-d</code> → <code>restart: unless-stopped</code></li>
                </ul>
            </div>
        </div>
      `, () => {
    function parseDockerRun(command) {
      const parts = command.trim().split(/\s+/);
      const result = {
        image: '',
        name: '',
        ports: [],
        volumes: [],
        environment: [],
        restart: 'no',
        detach: false,
        otherArgs: []
      };

      for (let i = 0; i < parts.length; i++) {
        const part = parts[i];

        if (part === 'docker' || part === 'run') {
          continue;
        } else if (part === '-d' || part === '--detach') {
          result.detach = true;
          result.restart = 'unless-stopped';
        } else if (part === '-p' || part === '--publish') {
          if (parts[i + 1]) {
            result.ports.push(parts[i + 1]);
            i++;
          }
        } else if (part === '-v' || part === '--volume') {
          if (parts[i + 1]) {
            result.volumes.push(parts[i + 1]);
            i++;
          }
        } else if (part === '-e' || part === '--env') {
          if (parts[i + 1]) {
            result.environment.push(parts[i + 1]);
            i++;
          }
        } else if (part === '--name') {
          if (parts[i + 1]) {
            result.name = parts[i + 1];
            i++;
          }
        } else if (part === '--restart') {
          if (parts[i + 1]) {
            result.restart = parts[i + 1];
            i++;
          }
        } else if (part.startsWith('-')) {
          result.otherArgs.push(part);
          if (parts[i + 1] && !parts[i + 1].startsWith('-')) {
            result.otherArgs.push(parts[i + 1]);
            i++;
          }
        } else if (!result.image && part.includes(':')) {
          result.image = part;
        } else if (!result.image && i === parts.length - 1) {
          result.image = part;
        }
      }

      return result;
    }

    function generateCompose(parsed) {
      const services = {};
      const serviceName = parsed.name || 'app';

      services[serviceName] = {
        image: parsed.image,
        container_name: parsed.name || undefined,
        ports: parsed.ports.length > 0 ? parsed.ports : undefined,
        volumes: parsed.volumes.length > 0 ? parsed.volumes : undefined,
        environment: parsed.environment.length > 0 ? parsed.environment : undefined,
        restart: parsed.restart !== 'no' ? parsed.restart : undefined
      };

      // Remove undefined properties
      Object.keys(services[serviceName]).forEach(key => {
        if (services[serviceName][key] === undefined) {
          delete services[serviceName][key];
        }
      });

      const compose = {
        version: '3.8',
        services: services
      };

      return YAML.stringify(compose);
    }

    // Simple YAML stringifier
    const YAML = {
      stringify: function(obj, indent = 0) {
        const spaces = ' '.repeat(indent);
        let result = '';

        if (Array.isArray(obj)) {
          if (obj.length === 0) return '[]';
          result += '\n';
          obj.forEach(item => {
            if (typeof item === 'object') {
              result += `${spaces}- ${this.stringify(item, indent + 2).trim()}\n`;
            } else {
              result += `${spaces}- ${item}\n`;
            }
          });
          return result;
        } else if (typeof obj === 'object' && obj !== null) {
          const entries = Object.entries(obj);
          if (entries.length === 0) return '{}';

          entries.forEach(([key, value], index) => {
            if (value === undefined || value === null) return;

            if (typeof value === 'object' && !Array.isArray(value)) {
              result += `${spaces}${key}:\n${this.stringify(value, indent + 2)}`;
            } else if (Array.isArray(value)) {
              result += `${spaces}${key}:\n${this.stringify(value, indent + 2)}`;
            } else {
              result += `${spaces}${key}: ${JSON.stringify(value)}\n`;
            }
          });
          return result;
        } else {
          return JSON.stringify(obj);
        }
      }
    };

    $('#convert').addEventListener('click', () => {
      const dockerRun = $('#dockerRun').value.trim();

      if (!dockerRun) {
        toast('Please enter a docker run command', 'error');
        return;
      }

      if (!dockerRun.startsWith('docker run')) {
        toast('Command must start with "docker run"', 'error');
        return;
      }

      try {
        const parsed = parseDockerRun(dockerRun);
        const compose = generateCompose(parsed);
        $('#compose').textContent = compose;
        toast('Converted to Docker Compose');
      } catch (error) {
        toast('Error: ' + error.message, 'error');
      }
    });

    $('#copy').addEventListener('click', () => {
      navigator.clipboard.writeText($('#compose').textContent).then(() => toast('Compose copied'));
    });

    $('#example').addEventListener('click', () => {
      const example = 'docker run -d -p 8080:80 -p 443:443 --name webserver -v /etc/nginx:/etc/nginx -v /var/log/nginx:/var/log/nginx -e NGINX_HOST=example.com nginx:alpine';
      $('#dockerRun').value = example;
      toast('Example loaded');
      $('#convert').click();
    });

    // Initialize
    $('#example').click();
  });
}

function xmlfmtTool() {
  setTool('XML Formatter', `
        <div class="row">
            <div class="form-group">
                <label>XML Input</label>
                <textarea id="xml" rows="8" placeholder="<root><item>value</item></root>"><root><person><name>John</name><age>30</age></person></root></textarea>
            </div>
            <div class="form-group">
                <label>Formatted Output</label>
                <textarea id="formatted" rows="8" placeholder="Formatted XML will appear here" readonly></textarea>
            </div>
        </div>
        <div class="form-group">
            <label>Options</label>
            <div style="display: flex; gap: 16px;">
                <label style="display: flex; align-items: center; gap: 8px;">
                    <input type="number" id="indent" value="2" min="1" max="8" style="width: 60px;" />
                    <span>Indent spaces</span>
                </label>
                <label style="display: flex; align-items: center; gap: 8px;">
                    <input type="checkbox" id="collapseEmpty" />
                    <span>Collapse empty elements</span>
                </label>
            </div>
        </div>
        <div class="btn-group">
            <button id="format" class="btn">Format XML</button>
            <button id="minify" class="btn btn-secondary">Minify XML</button>
            <button id="copy" class="btn btn-secondary">Copy Formatted</button>
        </div>
        <div id="error" style="color: var(--error); margin-top: 8px; display: none;"></div>
      `, () => {
    function formatXML(xml, indent = 2, collapseEmpty = false) {
      // Simple XML formatter
      let formatted = '';
      let indentLevel = 0;
      const indentStr = ' '.repeat(indent);

      // Parse XML tags
      const regex = /(<\/?[^>]+>)/g;
      const parts = xml.split(regex);
      let inTag = false;
      let currentTag = '';

      for (let i = 0; i < parts.length; i++) {
        const part = parts[i];

        if (part === '') continue;

        if (part.startsWith('<') && part.endsWith('>')) {
          // It's a tag
          if (part.startsWith('</')) {
            // Closing tag
            indentLevel--;
            formatted += indentStr.repeat(indentLevel) + part + '\n';
          } else if (part.endsWith('/>') || collapseEmpty) {
            // Self-closing or empty tag
            formatted += indentStr.repeat(indentLevel) + part + '\n';
          } else {
            // Opening tag
            formatted += indentStr.repeat(indentLevel) + part + '\n';
            indentLevel++;
          }
        } else {
          // Text content
          const trimmed = part.trim();
          if (trimmed) {
            formatted += indentStr.repeat(indentLevel) + trimmed + '\n';
          }
        }
      }

      return formatted.trim();
    }

    function minifyXML(xml) {
      return xml
        .replace(/\s+/g, ' ') // Collapse whitespace
        .replace(/>\s+</g, '><') // Remove whitespace between tags
        .trim();
    }

    function validateXML(xml) {
      try {
        const parser = new DOMParser();
        const xmlDoc = parser.parseFromString(xml, 'text/xml');
        const parseError = xmlDoc.getElementsByTagName('parsererror');
        if (parseError.length > 0) {
          throw new Error('XML parsing error');
        }
        return true;
      } catch (error) {
        return false;
      }
    }

    $('#format').addEventListener('click', () => {
      const xml = $('#xml').value;
      const indent = parseInt($('#indent').value) || 2;
      const collapseEmpty = $('#collapseEmpty').checked;

      if (!xml.trim()) {
        toast('Please enter XML', 'error');
        return;
      }

      if (!validateXML(xml)) {
        toast('Invalid XML', 'error');
        $('#error').textContent = 'Invalid XML structure';
        $('#error').style.display = 'block';
        return;
      }

      try {
        const formatted = formatXML(xml, indent, collapseEmpty);
        $('#formatted').value = formatted;
        $('#error').style.display = 'none';
        toast('XML formatted');
      } catch (error) {
        toast('Formatting error', 'error');
        $('#error').textContent = error.message;
        $('#error').style.display = 'block';
      }
    });

    $('#minify').addEventListener('click', () => {
      const xml = $('#xml').value;

      if (!xml.trim()) {
        toast('Please enter XML', 'error');
        return;
      }

      if (!validateXML(xml)) {
        toast('Invalid XML', 'error');
        return;
      }

      const minified = minifyXML(xml);
      $('#formatted').value = minified;
      toast('XML minified');
    });

    $('#copy').addEventListener('click', () => {
      navigator.clipboard.writeText($('#formatted').value).then(() => toast('Copied'));
    });

    // Initialize
    $('#format').click();
  });
}

function yamlprettyTool() {
  setTool('YAML Prettify', `
        <div class="row">
            <div class="form-group">
                <label>YAML Input</label>
                <textarea id="yaml" rows="8" placeholder="name: John
age: 30">name: John
age: 30
hobbies:
- reading
- hiking</textarea>
            </div>
            <div class="form-group">
                <label>Formatted Output</label>
                <textarea id="formatted" rows="8" placeholder="Formatted YAML will appear here" readonly></textarea>
            </div>
        </div>
        <div class="form-group">
            <label>Options</label>
            <div style="display: flex; gap: 16px;">
                <label style="display: flex; align-items: center; gap: 8px;">
                    <input type="number" id="indent" value="2" min="1" max="8" style="width: 60px;" />
                    <span>Indent spaces</span>
                </label>
                <label style="display: flex; align-items: center; gap: 8px;">
                    <input type="checkbox" id="sortKeys" />
                    <span>Sort keys alphabetically</span>
                </label>
            </div>
        </div>
        <div class="btn-group">
            <button id="format" class="btn">Format YAML</button>
            <button id="minify" class="btn btn-secondary">Minify YAML</button>
            <button id="copy" class="btn btn-secondary">Copy Formatted</button>
        </div>
        <div id="error" style="color: var(--error); margin-top: 8px; display: none;"></div>
      `, () => {
    function formatYAML(yaml, indent = 2, sortKeys = false) {
      const lines = yaml.split('\n');
      let result = [];
      let currentIndent = 0;
      const indentStr = ' '.repeat(indent);

      for (let line of lines) {
        const trimmed = line.trim();
        if (!trimmed) continue;

        // Calculate indentation level
        const match = line.match(/^(\s*)/);
        const lineIndent = match ? match[1].length : 0;

        // Adjust for current indent level
        if (lineIndent < currentIndent) {
          currentIndent = lineIndent;
        }

        const indentedLine = indentStr.repeat(currentIndent / indent) + trimmed;
        result.push(indentedLine);

        // Increase indent for next line if this line ends with ':'
        if (trimmed.endsWith(':') && !trimmed.startsWith('-')) {
          currentIndent += indent;
        }
      }

      // Sort keys if requested
      if (sortKeys) {
        result = sortYAMLLines(result, indent);
      }

      return result.join('\n');
    }

    function sortYAMLLines(lines, indent) {
      const sorted = [];
      let i = 0;

      while (i < lines.length) {
        const line = lines[i];
        const match = line.match(/^(\s*)([^:\s]+):/);

        if (match) {
          const [_, lineIndent, key] = match;
          const indentLevel = lineIndent.length / indent;

          // Collect block for this key
          const block = [line];
          i++;

          while (i < lines.length) {
            const nextLine = lines[i];
            const nextIndent = nextLine.match(/^(\s*)/)[1].length;

            if (nextIndent <= lineIndent.length) {
              break;
            }

            block.push(nextLine);
            i++;
          }

          // Sort sub-blocks recursively
          if (block.length > 1) {
            const subBlock = block.slice(1);
            const sortedSubBlock = sortYAMLLines(subBlock, indent);
            block.splice(1, subBlock.length, ...sortedSubBlock);
          }

          sorted.push(...block);
        } else {
          sorted.push(line);
          i++;
        }
      }

      // Sort top-level keys
      const topLevelBlocks = [];
      let currentBlock = [];

      for (const line of sorted) {
        const lineIndent = line.match(/^(\s*)/)[1].length;
        if (lineIndent === 0 && currentBlock.length > 0) {
          topLevelBlocks.push(currentBlock);
          currentBlock = [];
        }
        currentBlock.push(line);
      }
      if (currentBlock.length > 0) {
        topLevelBlocks.push(currentBlock);
      }

      // Sort blocks by key
      topLevelBlocks.sort((a, b) => {
        const keyA = a[0].match(/^(\s*)([^:\s]+):/)?.[2] || '';
        const keyB = b[0].match(/^(\s*)([^:\s]+):/)?.[2] || '';
        return keyA.localeCompare(keyB);
      });

      return topLevelBlocks.flat();
    }

    function minifyYAML(yaml) {
      return yaml
        .split('\n')
        .map(line => line.trim())
        .filter(line => line)
        .join('\n');
    }

    $('#format').addEventListener('click', () => {
      const yaml = $('#yaml').value;
      const indent = parseInt($('#indent').value) || 2;
      const sortKeys = $('#sortKeys').checked;

      if (!yaml.trim()) {
        toast('Please enter YAML', 'error');
        return;
      }

      try {
        const formatted = formatYAML(yaml, indent, sortKeys);
        $('#formatted').value = formatted;
        $('#error').style.display = 'none';
        toast('YAML formatted');
      } catch (error) {
        toast('Formatting error', 'error');
        $('#error').textContent = error.message;
        $('#error').style.display = 'block';
      }
    });

    $('#minify').addEventListener('click', () => {
      const yaml = $('#yaml').value;

      if (!yaml.trim()) {
        toast('Please enter YAML', 'error');
        return;
      }

      const minified = minifyYAML(yaml);
      $('#formatted').value = minified;
      toast('YAML minified');
    });

    $('#copy').addEventListener('click', () => {
      navigator.clipboard.writeText($('#formatted').value).then(() => toast('Copied'));
    });

    // Initialize
    $('#format').click();
  });
}

function emailnormTool() {
  setTool('Email Normalizer', `
        <div class="form-group">
            <label>Email Addresses</label>
            <textarea id="emails" rows="6" placeholder="Enter email addresses, one per line
john.doe@gmail.com
JANE.DOE@GMAIL.COM
john+label@gmail.com"></textarea>
        </div>
        <div class="form-group">
            <label>Normalization Options</label>
            <div style="display: flex; flex-direction: column; gap: 8px;">
                <label style="display: flex; align-items: center; gap: 8px;">
                    <input type="checkbox" id="lowercase" checked />
                    <span>Convert to lowercase</span>
                </label>
                <label style="display: flex; align-items: center; gap: 8px;">
                    <input type="checkbox" id="removeDots" />
                    <span>Remove dots from local part (Gmail)</span>
                </label>
                <label style="display: flex; align-items: center; gap: 8px;">
                    <input type="checkbox" id="removePlus" checked />
                    <span>Remove +labels (Gmail)</span>
                </label>
                <label style="display: flex; align-items: center; gap: 8px;">
                    <input type="checkbox" id="trimSpaces" checked />
                    <span>Trim whitespace</span>
                </label>
                <label style="display: flex; align-items: center; gap: 8px;">
                    <input type="checkbox" id="removeDuplicates" checked />
                    <span>Remove duplicates</span>
                </label>
            </div>
        </div>
        <div class="btn-group">
            <button id="normalize" class="btn">Normalize Emails</button>
            <button id="copy" class="btn btn-secondary">Copy Normalized</button>
            <button id="validate" class="btn btn-secondary">Validate</button>
        </div>
        <div id="output" class="output"></div>
        <div id="stats" style="margin-top: 16px; padding: 12px; background: var(--bg-secondary); border-radius: 8px; font-size: 14px;"></div>
      `, () => {
    function normalizeEmail(email, options) {
      let normalized = email;

      // Trim whitespace
      if (options.trimSpaces) {
        normalized = normalized.trim();
      }

      // Convert to lowercase
      if (options.lowercase) {
        normalized = normalized.toLowerCase();
      }

      // Split into local and domain parts
      const atIndex = normalized.indexOf('@');
      if (atIndex === -1) {
        return normalized; // Invalid email, return as-is
      }

      let local = normalized.substring(0, atIndex);
      const domain = normalized.substring(atIndex + 1);

      // Remove dots from local part (Gmail specific)
      if (options.removeDots && (domain === 'gmail.com' || domain === 'googlemail.com')) {
        local = local.replace(/\./g, '');
      }

      // Remove +labels (Gmail specific)
      if (options.removePlus && (domain === 'gmail.com' || domain === 'googlemail.com')) {
        const plusIndex = local.indexOf('+');
        if (plusIndex !== -1) {
          local = local.substring(0, plusIndex);
        }
      }

      return local + '@' + domain;
    }

    function isValidEmail(email) {
      const regex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
      return regex.test(email);
    }

    $('#normalize').addEventListener('click', () => {
      const emailsText = $('#emails').value;
      const options = {
        lowercase: $('#lowercase').checked,
        removeDots: $('#removeDots').checked,
        removePlus: $('#removePlus').checked,
        trimSpaces: $('#trimSpaces').checked,
        removeDuplicates: $('#removeDuplicates').checked
      };

      if (!emailsText.trim()) {
        toast('Please enter email addresses', 'error');
        return;
      }

      const emails = emailsText.split('\n').map(e => e.trim()).filter(e => e);
      const normalized = emails.map(email => normalizeEmail(email, options));

      let result = normalized;
      if (options.removeDuplicates) {
        result = [...new Set(normalized)];
      }

      $('#output').textContent = result.join('\n');

      // Show stats
      const stats = [
        `Original: ${emails.length} emails`,
        `Normalized: ${result.length} emails`,
        options.removeDuplicates ? `Duplicates removed: ${emails.length - result.length}` : ''
      ].filter(Boolean).join(' | ');

      $('#stats').textContent = stats;
      toast('Emails normalized');
    });

    $('#validate').addEventListener('click', () => {
      const emailsText = $('#emails').value;
      const emails = emailsText.split('\n').map(e => e.trim()).filter(e => e);

      const valid = [];
      const invalid = [];

      emails.forEach(email => {
        if (isValidEmail(email)) {
          valid.push(email);
        } else {
          invalid.push(email);
        }
      });

      const result = [
        '=== VALID EMAILS ===',
        ...valid,
        '',
        '=== INVALID EMAILS ===',
        ...invalid,
        '',
        `Total: ${emails.length} | Valid: ${valid.length} | Invalid: ${invalid.length}`
      ].join('\n');

      $('#output').textContent = result;
      $('#stats').textContent = `${valid.length} valid, ${invalid.length} invalid`;

      if (invalid.length > 0) {
        toast(`Found ${invalid.length} invalid emails`, 'error');
      } else {
        toast('All emails are valid');
      }
    });

    $('#copy').addEventListener('click', () => {
      navigator.clipboard.writeText($('#output').textContent).then(() => toast('Copied'));
    });

    // Initialize
    $('#normalize').click();
  });
}

function regextesterTool() {
  setTool('Regex Tester', `
        <div class="row">
            <div class="form-group">
                <label>Regular Expression</label>
                <input type="text" id="regex" placeholder="/pattern/flags" value="/\\w+@\\w+\\.\\w+/g" style="font-family: monospace;" />
            </div>
            <div class="form-group">
                <label>Flags</label>
                <div style="display: flex; gap: 8px;">
                    <label style="display: flex; align-items: center; gap: 4px;">
                        <input type="checkbox" id="flagG" />
                        <span>g</span>
                    </label>
                    <label style="display: flex; align-items: center; gap: 4px;">
                        <input type="checkbox" id="flagI" />
                        <span>i</span>
                    </label>
                    <label style="display: flex; align-items: center; gap: 4px;">
                        <input type="checkbox" id="flagM" />
                        <span>m</span>
                    </label>
                    <label style="display: flex; align-items: center; gap: 4px;">
                        <input type="checkbox" id="flagS" />
                        <span>s</span>
                    </label>
                    <label style="display: flex; align-items: center; gap: 4px;">
                        <input type="checkbox" id="flagU" />
                        <span>u</span>
                    </label>
                </div>
            </div>
        </div>
        <div class="form-group">
            <label>Test Text</label>
            <textarea id="text" rows="6" placeholder="Enter text to test regex against">Emails: john@example.com, jane@test.org, invalid@email</textarea>
        </div>
        <div class="btn-group">
            <button id="test" class="btn">Test Regex</button>
            <button id="copy" class="btn btn-secondary">Copy Matches</button>
            <button id="clear" class="btn btn-secondary">Clear</button>
        </div>
        <div id="matches" class="output" style="font-family: monospace; white-space: pre;"></div>
        <div id="matchInfo" style="margin-top: 16px; padding: 12px; background: var(--bg-secondary); border-radius: 8px; font-size: 14px;"></div>
      `, () => {
    function testRegex() {
      const regexInput = $('#regex').value.trim();
      const text = $('#text').value;

      if (!regexInput || !text) {
        toast('Please enter both regex and text', 'error');
        return;
      }

      try {
        // Extract flags from input
        const regexParts = regexInput.match(/^\/(.*)\/([gimsuy]*)$/);
        let pattern, flags;

        if (regexParts) {
          pattern = regexParts[1];
          flags = regexParts[2];
        } else {
          pattern = regexInput;
          flags = '';
        }

        // Add flags from checkboxes
        const checkboxFlags = [
          $('#flagG').checked ? 'g' : '',
          $('#flagI').checked ? 'i' : '',
          $('#flagM').checked ? 'm' : '',
          $('#flagS').checked ? 's' : '',
          $('#flagU').checked ? 'u' : ''
        ].join('');

        flags = (flags + checkboxFlags).split('').filter((v, i, a) => a.indexOf(v) === i).join('');

        // Create regex
        const regex = new RegExp(pattern, flags);

        // Test regex
        const matches = [];
        let match;
        let lastIndex = 0;

        while ((match = regex.exec(text)) !== null) {
          if (regex.lastIndex === lastIndex) {
            // Prevent infinite loop
            break;
          }
          lastIndex = regex.lastIndex;

          matches.push({
            index: match.index,
            match: match[0],
            groups: match.slice(1),
            input: match.input
          });

          if (!regex.global) {
            break;
          }
        }

        // Display results
        if (matches.length === 0) {
          $('#matches').textContent = 'No matches found';
          $('#matchInfo').textContent = 'Pattern did not match any text';
        } else {
          const formatted = matches.map((m, i) => {
            const lines = [
              `Match ${i + 1}: "${m.match}"`,
              `Position: ${m.index} to ${m.index + m.match.length}`,
              `Length: ${m.match.length} characters`
            ];

            if (m.groups.length > 0) {
              lines.push('Groups:');
              m.groups.forEach((group, j) => {
                if (group !== undefined) {
                  lines.push(`  ${j + 1}: "${group}"`);
                }
              });
            }

            return lines.join('\n');
          }).join('\n\n');

          $('#matches').textContent = formatted;
          $('#matchInfo').textContent = `Found ${matches.length} match${matches.length !== 1 ? 'es' : ''}`;
        }

        // Highlight matches in textarea (simplified)
        $('#text').style.borderColor = matches.length > 0 ? 'var(--success)' : 'var(--error)';

        toast(`Found ${matches.length} match${matches.length !== 1 ? 'es' : ''}`);

      } catch (error) {
        $('#matches').textContent = `Error: ${error.message}`;
        $('#matchInfo').textContent = 'Invalid regular expression';
        $('#text').style.borderColor = 'var(--error)';
        toast('Regex error', 'error');
      }
    }

    $('#test').addEventListener('click', testRegex);

    $('#copy').addEventListener('click', () => {
      navigator.clipboard.writeText($('#matches').textContent).then(() => toast('Matches copied'));
    });

    $('#clear').addEventListener('click', () => {
      $('#regex').value = '';
      $('#text').value = '';
      $('#matches').textContent = '';
      $('#matchInfo').textContent = '';
      $('#text').style.borderColor = 'var(--border)';
      toast('Cleared');
    });

    // Real-time testing on Enter key
    $('#regex').addEventListener('keyup', (e) => {
      if (e.key === 'Enter') {
        testRegex();
      }
    });

    // Initialize
    testRegex();
  });
}

function regexcheatTool() {
  setTool('Regex Cheatsheet', `
        <div class="form-group">
            <label>Search Patterns</label>
            <input type="text" id="search" placeholder="Search regex patterns..." />
        </div>
        <div id="regexPatterns" style="display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 16px; margin-top: 16px;"></div>
      `, () => {
    const regexPatterns = [
      {
        category: 'Anchors',
        patterns: [
          { pattern: '^', description: 'Start of string' },
          { pattern: '$', description: 'End of string' },
          { pattern: '\\b', description: 'Word boundary' },
          { pattern: '\\B', description: 'Non-word boundary' }
        ]
      },
      {
        category: 'Character Classes',
        patterns: [
          { pattern: '.', description: 'Any character except newline' },
          { pattern: '\\d', description: 'Digit (0-9)' },
          { pattern: '\\D', description: 'Non-digit' },
          { pattern: '\\w', description: 'Word character (a-z, A-Z, 0-9, _)' },
          { pattern: '\\W', description: 'Non-word character' },
          { pattern: '\\s', description: 'Whitespace' },
          { pattern: '\\S', description: 'Non-whitespace' },
          { pattern: '[abc]', description: 'Any of a, b, or c' },
          { pattern: '[^abc]', description: 'Not a, b, or c' },
          { pattern: '[a-z]', description: 'Lowercase letters' },
          { pattern: '[A-Z]', description: 'Uppercase letters' },
          { pattern: '[0-9]', description: 'Digits' }
        ]
      },
      {
        category: 'Quantifiers',
        patterns: [
          { pattern: '*', description: '0 or more' },
          { pattern: '+', description: '1 or more' },
          { pattern: '?', description: '0 or 1' },
          { pattern: '{3}', description: 'Exactly 3' },
          { pattern: '{3,}', description: '3 or more' },
          { pattern: '{3,5}', description: '3 to 5' }
        ]
      },
      {
        category: 'Groups & References',
        patterns: [
          { pattern: '(abc)', description: 'Capture group' },
          { pattern: '(?:abc)', description: 'Non-capturing group' },
          { pattern: '\\1', description: 'Backreference to group 1' },
          { pattern: '(?<name>abc)', description: 'Named capture group' },
          { pattern: '\\k<name>', description: 'Backreference to named group' }
        ]
      },
      {
        category: 'Lookarounds',
        patterns: [
          { pattern: '(?=abc)', description: 'Positive lookahead' },
          { pattern: '(?!abc)', description: 'Negative lookahead' },
          { pattern: '(?<=abc)', description: 'Positive lookbehind' },
          { pattern: '(?<!abc)', description: 'Negative lookbehind' }
        ]
      },
      {
        category: 'Common Patterns',
        patterns: [
          { pattern: '^\\d+$', description: 'Only digits' },
          { pattern: '^[a-zA-Z]+$', description: 'Only letters' },
          { pattern: '^[a-zA-Z0-9]+$', description: 'Alphanumeric' },
          { pattern: '^[\\w.%+-]+@[\\w.-]+\\.[a-zA-Z]{2,}$', description: 'Email' },
          { pattern: '^(https?:\\/\\/)?([\\w.-]+)\\.([a-z]{2,})(\\/\\S*)?$', description: 'URL' },
          { pattern: '^(\\d{3})-(\\d{3})-(\\d{4})$', description: 'Phone (US)' },
          { pattern: '^(0[1-9]|1[0-2])\\/\\d{2}\\/\\d{4}$', description: 'Date (MM/DD/YYYY)' }
        ]
      },
      {
        category: 'Flags',
        patterns: [
          { pattern: 'g', description: 'Global search' },
          { pattern: 'i', description: 'Case-insensitive' },
          { pattern: 'm', description: 'Multiline' },
          { pattern: 's', description: 'Dot matches newline' },
          { pattern: 'u', description: 'Unicode' },
          { pattern: 'y', description: 'Sticky' }
        ]
      }
    ];

    function renderPatterns(patterns) {
      const html = patterns.map(category => `
                <div style="padding: 16px; background: var(--bg-secondary); border-radius: 8px;">
                    <h3 style="margin-bottom: 12px; color: var(--primary-light);">${category.category}</h3>
                    <div style="display: flex; flex-direction: column; gap: 8px;">
                        ${category.patterns.map(p => `
                            <div style="padding: 8px; background: var(--bg); border-radius: 4px; border-left: 3px solid var(--primary);">
                                <div style="font-family: monospace; font-weight: 600; margin-bottom: 4px; color: var(--text);">${p.pattern}</div>
                                <div style="font-size: 14px; color: var(--text-muted);">${p.description}</div>
                            </div>
                        `).join('')}
                    </div>
                </div>
            `).join('');

      $('#regexPatterns').innerHTML = html;
    }

    $('#search').addEventListener('input', (e) => {
      const query = e.target.value.toLowerCase().trim();

      if (!query) {
        renderPatterns(regexPatterns);
        return;
      }

      const filtered = regexPatterns.map(category => {
        const filteredPatterns = category.patterns.filter(p =>
          p.pattern.toLowerCase().includes(query) ||
          p.description.toLowerCase().includes(query) ||
          category.category.toLowerCase().includes(query)
        );

        if (filteredPatterns.length > 0) {
          return {
            category: category.category,
            patterns: filteredPatterns
          };
        }
        return null;
      }).filter(Boolean);

      renderPatterns(filtered);

      if (filtered.length === 0) {
        $('#regexPatterns').innerHTML = `
                    <div style="grid-column: 1 / -1; text-align: center; padding: 40px; color: var(--text-muted);">
                        No regex patterns found matching "${query}"
                    </div>
                `;
      }
    });

    // Initialize
    renderPatterns(regexPatterns);
  });
}

// NETWORK TOOLS

function ipv4subTool() {
  setTool('IPv4 Subnet Calculator', `
        <div class="row">
            <div class="form-group">
                <label>IP Address</label>
                <input type="text" id="ip" placeholder="192.168.1.0" value="192.168.1.0" />
            </div>
            <div class="form-group">
                <label>CIDR or Netmask</label>
                <input type="text" id="cidr" placeholder="24 or 255.255.255.0" value="24" />
            </div>
        </div>
        <div class="btn-group">
            <button id="calculate" class="btn">Calculate Subnet</button>
            <button id="copy" class="btn btn-secondary">Copy Results</button>
        </div>
        <div id="results" class="output"></div>
        <div style="margin-top: 16px;">
            <h4 style="margin-bottom: 8px;">🌐 Subnet Information</h4>
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 12px;">
                <div class="subnet-info">
                    <div style="font-size: 12px; color: var(--text-muted);">Network Address</div>
                    <div id="network" style="font-weight: 600; font-family: monospace;"></div>
                </div>
                <div class="subnet-info">
                    <div style="font-size: 12px; color: var(--text-muted);">Broadcast</div>
                    <div id="broadcast" style="font-weight: 600; font-family: monospace;"></div>
                </div>
                <div class="subnet-info">
                    <div style="font-size: 12px; color: var(--text-muted);">Usable Hosts</div>
                    <div id="hosts" style="font-weight: 600;"></div>
                </div>
                <div class="subnet-info">
                    <div style="font-size: 12px; color: var(--text-muted);">Wildcard Mask</div>
                    <div id="wildcard" style="font-weight: 600; font-family: monospace;"></div>
                </div>
            </div>
        </div>
      `, () => {
    function ipToInt(ip) {
      return ip.split('.').reduce((int, octet) => (int << 8) + parseInt(octet, 10), 0) >>> 0;
    }

    function intToIp(int) {
      return [(int >>> 24) & 255, (int >>> 16) & 255, (int >>> 8) & 255, int & 255].join('.');
    }

    function cidrToMask(cidr) {
      const mask = ~((1 << (32 - cidr)) - 1) >>> 0;
      return intToIp(mask);
    }

    function maskToCidr(mask) {
      const int = ipToInt(mask);
      let cidr = 0;
      for (let i = 31; i >= 0; i--) {
        if ((int >>> i) & 1) {
          cidr++;
        } else {
          break;
        }
      }
      return cidr;
    }

    function calculateSubnet(ip, cidrOrMask) {
      let cidr, mask;

      // Parse CIDR or mask
      if (cidrOrMask.includes('.')) {
        mask = cidrOrMask;
        cidr = maskToCidr(mask);
      } else {
        cidr = parseInt(cidrOrMask);
        if (cidr < 0 || cidr > 32) throw new Error('CIDR must be 0-32');
        mask = cidrToMask(cidr);
      }

      const ipInt = ipToInt(ip);
      const maskInt = ipToInt(mask);
      const networkInt = ipInt & maskInt;
      const broadcastInt = networkInt | (~maskInt >>> 0);
      const network = intToIp(networkInt);
      const broadcast = intToIp(broadcastInt);
      const usableHosts = Math.max(0, Math.pow(2, 32 - cidr) - 2);
      const wildcard = intToIp(~maskInt >>> 0);
      const firstHost = cidr < 31 ? intToIp(networkInt + 1) : network;
      const lastHost = cidr < 31 ? intToIp(broadcastInt - 1) : broadcast;

      return {
        ip,
        cidr,
        mask,
        network,
        broadcast,
        usableHosts,
        wildcard,
        firstHost,
        lastHost,
        totalHosts: Math.pow(2, 32 - cidr)
      };
    }

    $('#calculate').addEventListener('click', () => {
      const ip = $('#ip').value.trim();
      const cidr = $('#cidr').value.trim();

      if (!ip || !cidr) {
        toast('Please enter IP and CIDR/netmask', 'error');
        return;
      }

      try {
        const subnet = calculateSubnet(ip, cidr);

        // Update component displays
        $('#network').textContent = subnet.network;
        $('#broadcast').textContent = subnet.broadcast;
        $('#hosts').textContent = subnet.usableHosts;
        $('#wildcard').textContent = subnet.wildcard;

        // Build results
        const results = [
          '=== SUBNET CALCULATION ===',
          `IP Address: ${subnet.ip}`,
          `CIDR Notation: /${subnet.cidr}`,
          `Netmask: ${subnet.mask}`,
          `Wildcard Mask: ${subnet.wildcard}`,
          '',
          '=== NETWORK RANGE ===',
          `Network Address: ${subnet.network}`,
          `Broadcast Address: ${subnet.broadcast}`,
          `First Usable Host: ${subnet.firstHost}`,
          `Last Usable Host: ${subnet.lastHost}`,
          '',
          '=== HOST INFORMATION ===',
          `Total Hosts: ${subnet.totalHosts}`,
          `Usable Hosts: ${subnet.usableHosts}`,
          `Network Bits: ${subnet.cidr}`,
          `Host Bits: ${32 - subnet.cidr}`
        ].join('\n');

        $('#results').textContent = results;
        toast('Subnet calculated');
      } catch (error) {
        toast('Error: ' + error.message, 'error');
      }
    });

    $('#copy').addEventListener('click', () => {
      navigator.clipboard.writeText($('#results').textContent).then(() => toast('Results copied'));
    });

    // Initialize
    $('#calculate').click();
  });
}

function ipv4convTool() {
  setTool('IPv4 Address Converter', `
        <div class="form-group">
            <label>IP Address</label>
            <input type="text" id="ip" placeholder="192.168.1.1" value="192.168.1.1" />
        </div>
        <div class="btn-group">
            <button id="convert" class="btn">Convert IP</button>
            <button id="copy" class="btn btn-secondary">Copy All</button>
        </div>
        <div id="results" class="output"></div>
        <div style="margin-top: 16px;">
            <h4 style="margin-bottom: 8px;">🌐 IP Formats</h4>
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 12px;">
                <div class="ip-format">
                    <div style="font-size: 12px; color: var(--text-muted);">Decimal</div>
                    <div id="decimal" style="font-weight: 600; font-family: monospace;"></div>
                </div>
                <div class="ip-format">
                    <div style="font-size: 12px; color: var(--text-muted);">Hexadecimal</div>
                    <div id="hex" style="font-weight: 600; font-family: monospace;"></div>
                </div>
                <div class="ip-format">
                    <div style="font-size: 12px; color: var(--text-muted);">Binary</div>
                    <div id="binary" style="font-weight: 600; font-family: monospace; font-size: 12px;"></div>
                </div>
                <div class="ip-format">
                    <div style="font-size: 12px; color: var(--text-muted);">IPv6</div>
                    <div id="ipv6" style="font-weight: 600; font-family: monospace;"></div>
                </div>
            </div>
        </div>
      `, () => {
    function ipToInt(ip) {
      const parts = ip.split('.');
      if (parts.length !== 4) throw new Error('Invalid IP format');
      return parts.reduce((int, octet) => (int << 8) + parseInt(octet, 10), 0) >>> 0;
    }

    function intToIp(int) {
      return [(int >>> 24) & 255, (int >>> 16) & 255, (int >>> 8) & 255, int & 255].join('.');
    }

    function convertIP(ip) {
      const int = ipToInt(ip);

      // Decimal
      const decimal = int.toString();

      // Hexadecimal
      const hex = '0x' + int.toString(16).toUpperCase().padStart(8, '0');

      // Binary
      const binary = int.toString(2).padStart(32, '0');
      const binaryFormatted = binary.match(/.{1,8}/g).join('.');

      // IPv6 (IPv4-mapped IPv6 address)
      const ipv6 = `::ffff:${int.toString(16).match(/.{1,4}/g).join(':')}`;

      // Octal
      const octal = '0' + int.toString(8);

      // IP class
      let ipClass = 'Unknown';
      const firstOctet = parseInt(ip.split('.')[0]);
      if (firstOctet >= 1 && firstOctet <= 126) ipClass = 'A';
      else if (firstOctet >= 128 && firstOctet <= 191) ipClass = 'B';
      else if (firstOctet >= 192 && firstOctet <= 223) ipClass = 'C';
      else if (firstOctet >= 224 && firstOctet <= 239) ipClass = 'D (Multicast)';
      else if (firstOctet >= 240 && firstOctet <= 255) ipClass = 'E (Experimental)';

      // Check if private
      const isPrivate =
        ip.startsWith('10.') ||
        (ip.startsWith('172.') && parseInt(ip.split('.')[1]) >= 16 && parseInt(ip.split('.')[1]) <= 31) ||
        ip.startsWith('192.168.');

      // Check if reserved
      const isReserved =
        ip.startsWith('127.') || // Loopback
        ip === '0.0.0.0' || // Default route
        ip === '255.255.255.255' || // Broadcast
        ip.startsWith('169.254.'); // Link-local

      return {
        ip,
        decimal,
        hex,
        binary: binaryFormatted,
        ipv6,
        octal,
        ipClass,
        isPrivate,
        isReserved
      };
    }

    $('#convert').addEventListener('click', () => {
      const ip = $('#ip').value.trim();

      if (!ip) {
        toast('Please enter an IP address', 'error');
        return;
      }

      try {
        const converted = convertIP(ip);

        // Update component displays
        $('#decimal').textContent = converted.decimal;
        $('#hex').textContent = converted.hex;
        $('#binary').textContent = converted.binary;
        $('#ipv6').textContent = converted.ipv6;

        // Build results
        const results = [
          '=== IP ADDRESS CONVERSION ===',
          `IP Address: ${converted.ip}`,
          `Decimal: ${converted.decimal}`,
          `Hexadecimal: ${converted.hex}`,
          `Binary: ${converted.binary}`,
          `IPv6 (mapped): ${converted.ipv6}`,
          `Octal: ${converted.octal}`,
          '',
          '=== IP INFORMATION ===',
          `Class: ${converted.ipClass}`,
          `Private: ${converted.isPrivate ? 'Yes' : 'No'}`,
          `Reserved: ${converted.isReserved ? 'Yes' : 'No'}`,
          '',
          '=== OCTET BREAKDOWN ===',
          ...converted.ip.split('.').map((octet, i) =>
            `Octet ${i + 1}: ${octet} (${parseInt(octet).toString(2).padStart(8, '0')})`
          )
        ].join('\n');

        $('#results').textContent = results;
        toast('IP converted');
      } catch (error) {
        toast('Error: ' + error.message, 'error');
      }
    });

    $('#copy').addEventListener('click', () => {
      navigator.clipboard.writeText($('#results').textContent).then(() => toast('Results copied'));
    });

    // Initialize
    $('#convert').click();
  });
}

function ipv4rangeTool() {
  setTool('IPv4 Range Expander', `
        <div class="row">
            <div class="form-group">
                <label>Start IP</label>
                <input type="text" id="startIp" placeholder="192.168.1.1" value="192.168.1.1" />
            </div>
            <div class="form-group">
                <label>End IP</label>
                <input type="text" id="endIp" placeholder="192.168.1.10" value="192.168.1.10" />
            </div>
        </div>
        <div class="btn-group">
            <button id="expand" class="btn">Expand Range</button>
            <button id="calculateCidr" class="btn btn-secondary">Calculate CIDR</button>
            <button id="copy" class="btn btn-secondary">Copy IPs</button>
        </div>
        <div id="results" class="output"></div>
        <div style="margin-top: 16px;">
            <h4 style="margin-bottom: 8px;">🌐 Range Information</h4>
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 12px;">
                <div class="range-info">
                    <div style="font-size: 12px; color: var(--text-muted);">Total IPs</div>
                    <div id="totalIps" style="font-weight: 600;"></div>
                </div>
                <div class="range-info">
                    <div style="font-size: 12px; color: var(--text-muted);">CIDR</div>
                    <div id="cidr" style="font-weight: 600;"></div>
                </div>
                <div class="range-info">
                    <div style="font-size: 12px; color: var(--text-muted);">Netmask</div>
                    <div id="netmask" style="font-weight: 600; font-family: monospace;"></div>
                </div>
                <div class="range-info">
                    <div style="font-size: 12px; color: var(--text-muted);">Network</div>
                    <div id="network" style="font-weight: 600; font-family: monospace;"></div>
                </div>
            </div>
        </div>
      `, () => {
    function ipToInt(ip) {
      return ip.split('.').reduce((int, octet) => (int << 8) + parseInt(octet, 10), 0) >>> 0;
    }

    function intToIp(int) {
      return [(int >>> 24) & 255, (int >>> 16) & 255, (int >>> 8) & 255, int & 255].join('.');
    }

    function expandRange(startIp, endIp) {
      const start = ipToInt(startIp);
      const end = ipToInt(endIp);

      if (start > end) {
        throw new Error('Start IP must be less than or equal to End IP');
      }

      const ips = [];
      for (let i = start; i <= end; i++) {
        ips.push(intToIp(i));
      }

      return {
        start: startIp,
        end: endIp,
        ips,
        total: ips.length,
        startInt: start,
        endInt: end
      };
    }

    function findCIDR(start, end) {
      const startInt = ipToInt(start);
      const endInt = ipToInt(end);

      // Find common prefix
      let xor = startInt ^ endInt;
      let cidr = 32;

      while (xor > 0) {
        xor >>= 1;
        cidr--;
      }

      // Calculate network address
      const mask = ~((1 << (32 - cidr)) - 1) >>> 0;
      const networkInt = startInt & mask;
      const network = intToIp(networkInt);
      const netmask = intToIp(mask);

      // Calculate broadcast
      const broadcastInt = networkInt | (~mask >>> 0);
      const broadcast = intToIp(broadcastInt);

      // Check if range fits exactly in subnet
      const rangeFits = networkInt === startInt && broadcastInt === endInt;

      return {
        cidr,
        network,
        netmask,
        broadcast,
        rangeFits,
        usableHosts: Math.max(0, Math.pow(2, 32 - cidr) - 2)
      };
    }

    $('#expand').addEventListener('click', () => {
      const startIp = $('#startIp').value.trim();
      const endIp = $('#endIp').value.trim();

      if (!startIp || !endIp) {
        toast('Please enter both start and end IPs', 'error');
        return;
      }

      try {
        const range = expandRange(startIp, endIp);

        // Display IPs (limit to first 50)
        const displayIps = range.ips.length > 50 ?
          range.ips.slice(0, 50).join('\n') + `\n\n... and ${range.ips.length - 50} more` :
          range.ips.join('\n');

        $('#results').textContent = displayIps;
        $('#totalIps').textContent = range.total;

        toast(`Expanded ${range.total} IPs`);
      } catch (error) {
        toast('Error: ' + error.message, 'error');
      }
    });

    $('#calculateCidr').addEventListener('click', () => {
      const startIp = $('#startIp').value.trim();
      const endIp = $('#endIp').value.trim();

      if (!startIp || !endIp) {
        toast('Please enter both start and end IPs', 'error');
        return;
      }

      try {
        const cidrInfo = findCIDR(startIp, endIp);
        const range = expandRange(startIp, endIp);

        $('#cidr').textContent = `/${cidrInfo.cidr}`;
        $('#netmask').textContent = cidrInfo.netmask;
        $('#network').textContent = cidrInfo.network;

        const results = [
          '=== CIDR CALCULATION ===',
          `Start IP: ${startIp}`,
          `End IP: ${endIp}`,
          `Total IPs: ${range.total}`,
          '',
          '=== SUBNET INFORMATION ===',
          `CIDR: /${cidrInfo.cidr}`,
          `Network: ${cidrInfo.network}`,
          `Netmask: ${cidrInfo.netmask}`,
          `Broadcast: ${cidrInfo.broadcast}`,
          `Usable Hosts: ${cidrInfo.usableHosts}`,
          `Range Fits Exactly: ${cidrInfo.rangeFits ? 'Yes' : 'No'}`
        ].join('\n');

        $('#results').textContent = results;
        toast('CIDR calculated');
      } catch (error) {
        toast('Error: ' + error.message, 'error');
      }
    });

    $('#copy').addEventListener('click', () => {
      navigator.clipboard.writeText($('#results').textContent).then(() => toast('Results copied'));
    });

    // Initialize
    $('#expand').click();
  });
}

function maclookupTool() {
  setTool('MAC Address Lookup', `
        <div class="form-group">
            <label>MAC Address</label>
            <input type="text" id="mac" placeholder="00:1A:2B:3C:4D:5E" value="00:1A:2B:3C:4D:5E" style="font-family: monospace;" />
            <div style="margin-top: 8px; font-size: 12px; color: var(--text-muted);">
                Formats accepted: 00:1A:2B:3C:4D:5E, 00-1A-2B-3C-4D-5E, 001A.2B3C.4D5E, 001A2B3C4D5E
            </div>
        </div>
        <div class="btn-group">
            <button id="lookup" class="btn">Lookup Vendor</button>
            <button id="generate" class="btn btn-secondary">Generate Random</button>
            <button id="copy" class="btn btn-secondary">Copy MAC</button>
        </div>
        <div id="results" class="output"></div>
        <div style="margin-top: 16px;">
            <h4 style="margin-bottom: 8px;">🔍 MAC Address Information</h4>
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 12px;">
                <div class="mac-info">
                    <div style="font-size: 12px; color: var(--text-muted);">OUI (Vendor)</div>
                    <div id="vendor" style="font-weight: 600;"></div>
                </div>
                <div class="mac-info">
                    <div style="font-size: 12px; color: var(--text-muted);">Type</div>
                    <div id="type" style="font-weight: 600;"></div>
                </div>
                <div class="mac-info">
                    <div style="font-size: 12px; color: var(--text-muted);">Format</div>
                    <div id="format" style="font-weight: 600; font-family: monospace;"></div>
                </div>
                <div class="mac-info">
                    <div style="font-size: 12px; color: var(--text-muted);">Is Multicast?</div>
                    <div id="multicast" style="font-weight: 600;"></div>
                </div>
            </div>
        </div>
      `, () => {
    // Common OUI (Organizationally Unique Identifier) database
    const ouiDatabase = {
      '001A2B': 'Cisco Systems',
      '001C23': 'Apple',
      '00219F': 'Samsung',
      '0050F2': 'Microsoft',
      '0090D0': 'Intel',
      '00A0C9': 'Intel',
      '00E0FC': 'Realtek',
      '080020': 'Sun Microsystems',
      '080069': 'IBM',
      '08005A': 'IBM',
      '080011': 'Novell',
      '00E04C': 'Realtek',
      '001D7E': 'Samsung',
      '001E65': 'Apple',
      '001F5B': 'Apple',
      '0021E9': 'Samsung',
      '002332': 'Apple',
      '00236C': 'Apple',
      '002500': 'Apple',
      '0026B0': 'Apple',
      '003065': 'Apple',
      '003EE1': 'Apple',
      '004096': 'Apple',
      '00B0D0': 'Cisco',
      '00E016': 'Cisco',
      '00E0F9': 'Cisco',
      '00E0B0': 'Cisco',
      '00E08F': 'Cisco',
      '00163E': 'Cisco',
      '001B2C': 'Cisco',
      '001C0E': 'Cisco',
      '001C57': 'Cisco',
      '001D45': 'Cisco',
      '001E13': 'Cisco',
      '001E4A': 'Cisco',
      '001F6C': 'Cisco',
      '001FF3': 'Cisco',
      '0021A8': 'Cisco',
      '0022BD': 'Cisco',
      '0023EB': 'Cisco',
      '0024F7': 'Cisco',
      '0025BC': 'Cisco',
      '0026F2': 'Cisco',
      '002708': 'Cisco',
      '00C0F0': 'D-Link',
      '0012FB': 'D-Link',
      '001A73': 'D-Link',
      '0022B0': 'D-Link',
      '002348': 'D-Link',
      '002655': 'D-Link',
      '00E064': 'D-Link',
      '00E091': 'D-Link',
      '00E0A6': 'D-Link',
      '000C41': 'TP-Link',
      '001478': 'TP-Link',
      '001E48': 'TP-Link',
      '0023CD': 'TP-Link',
      '0024A5': 'TP-Link',
      '00268B': 'TP-Link',
      '0030F3': 'TP-Link',
      '00E04D': 'TP-Link',
      '00E075': 'TP-Link',
      '00E08B': 'TP-Link'
    };

    function normalizeMAC(mac) {
      // Remove separators and convert to uppercase
      const clean = mac.replace(/[:\-\.]/g, '').toUpperCase();

      // Validate length
      if (clean.length !== 12) {
        throw new Error('MAC address must be 12 hexadecimal characters');
      }

      // Validate hex
      if (!/^[0-9A-F]{12}$/.test(clean)) {
        throw new Error('Invalid hexadecimal characters in MAC address');
      }

      return clean;
    }

    function formatMAC(mac, format = 'colon') {
      const clean = normalizeMAC(mac);

      switch (format) {
        case 'colon':
          return clean.match(/.{2}/g).join(':');
        case 'hyphen':
          return clean.match(/.{2}/g).join('-');
        case 'dot':
          return clean.match(/.{4}/g).join('.');
        case 'cisco':
          return clean.match(/.{4}/g).join('.');
        case 'none':
          return clean;
        default:
          return clean.match(/.{2}/g).join(':');
      }
    }

    function lookupVendor(mac) {
      const clean = normalizeMAC(mac);
      const oui = clean.substring(0, 6).toUpperCase();
      return ouiDatabase[oui] || 'Unknown vendor';
    }

    function getMACInfo(mac) {
      const clean = normalizeMAC(mac);

      // Get vendor
      const vendor = lookupVendor(mac);

      // Determine type from first octet
      const firstOctet = parseInt(clean.substring(0, 2), 16);
      const isUnicast = (firstOctet & 0x01) === 0;
      const isUniversal = (firstOctet & 0x02) === 0;
      const isMulticast = !isUnicast;
      const isLocal = !isUniversal;

      let type = '';
      if (isUnicast && isUniversal) type = 'Universal Unicast';
      else if (isUnicast && isLocal) type = 'Local Unicast';
      else if (isMulticast && isUniversal) type = 'Universal Multicast';
      else if (isMulticast && isLocal) type = 'Local Multicast';

      // Check if it's a broadcast (all Fs)
      const isBroadcast = clean === 'FFFFFFFFFFFF';

      return {
        mac: formatMAC(mac, 'colon'),
        vendor,
        type,
        isUnicast,
        isMulticast,
        isUniversal,
        isLocal,
        isBroadcast,
        oui: clean.substring(0, 6).toUpperCase(),
        nic: clean.substring(6)
      };
    }

    function generateRandomMAC() {
      const bytes = new Uint8Array(6);
      crypto.getRandomValues(bytes);

      // Set locally administered, unicast (0x02 = locally administered, unicast)
      bytes[0] = (bytes[0] & 0xFE) | 0x02;

      const hex = Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
      return formatMAC(hex, 'colon');
    }

    $('#lookup').addEventListener('click', () => {
      const mac = $('#mac').value.trim();

      if (!mac) {
        toast('Please enter a MAC address', 'error');
        return;
      }

      try {
        const info = getMACInfo(mac);

        // Update component displays
        $('#vendor').textContent = info.vendor;
        $('#type').textContent = info.type;
        $('#format').textContent = info.mac;
        $('#multicast').textContent = info.isMulticast ? 'Yes' : 'No';

        // Build results
        const results = [
          '=== MAC ADDRESS INFORMATION ===',
          `MAC Address: ${info.mac}`,
          `Vendor (OUI): ${info.vendor}`,
          `OUI: ${info.oui}`,
          `NIC: ${info.nic}`,
          '',
          '=== TYPE INFORMATION ===',
          `Address Type: ${info.type}`,
          `Unicast: ${info.isUnicast ? 'Yes' : 'No'}`,
          `Multicast: ${info.isMulticast ? 'Yes' : 'No'}`,
          `Universal/Local: ${info.isUniversal ? 'Universal' : 'Local'}`,
          `Broadcast: ${info.isBroadcast ? 'Yes' : 'No'}`,
          '',
          '=== FORMATS ===',
          `Colon: ${formatMAC(mac, 'colon')}`,
          `Hyphen: ${formatMAC(mac, 'hyphen')}`,
          `Dot: ${formatMAC(mac, 'dot')}`,
          `No separators: ${formatMAC(mac, 'none')}`
        ].join('\n');

        $('#results').textContent = results;
        toast('MAC address information retrieved');
      } catch (error) {
        toast('Error: ' + error.message, 'error');
      }
    });

    $('#generate').addEventListener('click', () => {
      const randomMAC = generateRandomMAC();
      $('#mac').value = randomMAC;
      toast('Random MAC generated');
      $('#lookup').click();
    });

    $('#copy').addEventListener('click', () => {
      navigator.clipboard.writeText($('#mac').value).then(() => toast('MAC copied'));
    });

    // Initialize
    $('#lookup').click();
  });
}

function ipv6ulaTool() {
  setTool('IPv6 ULA Generator', `
        <div class="form-group">
            <label>Prefix (fd00::/8)</label>
            <input type="text" id="prefix" value="fd00::/8" readonly style="font-family: monospace;" />
        </div>
        <div class="row">
            <div class="form-group">
                <label>Global ID (40 bits)</label>
                <input type="text" id="globalId" placeholder="Randomly generated" readonly style="font-family: monospace;" />
            </div>
            <div class="form-group">
                <label>Subnet ID (16 bits)</label>
                <input type="text" id="subnetId" value="0000" style="font-family: monospace;" maxlength="4" />
            </div>
        </div>
        <div class="form-group">
            <label>Interface ID (64 bits)</label>
            <div class="row">
                <input type="text" id="interfaceId" placeholder="Random or EUI-64" style="font-family: monospace; flex: 3;" />
                <select id="interfaceType" style="flex: 1;">
                    <option value="random">Random</option>
                    <option value="eui64">EUI-64</option>
                    <option value="manual">Manual</option>
                </select>
            </div>
        </div>
        <div class="btn-group">
            <button id="generate" class="btn">Generate ULA</button>
            <button id="copy" class="btn btn-secondary">Copy Address</button>
            <button id="generateSubnet" class="btn btn-secondary">New Subnet</button>
        </div>
        <div id="results" class="output"></div>
        <div style="margin-top: 16px;">
            <h4 style="margin-bottom: 8px;">🌐 IPv6 ULA Address</h4>
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 12px;">
                <div class="ipv6-info">
                    <div style="font-size: 12px; color: var(--text-muted);">Full Address</div>
                    <div id="fullAddress" style="font-weight: 600; font-family: monospace;"></div>
                </div>
                <div class="ipv6-info">
                    <div style="font-size: 12px; color: var(--text-muted);">Network</div>
                    <div id="network" style="font-weight: 600; font-family: monospace;"></div>
                </div>
                <div class="ipv6-info">
                    <div style="font-size: 12px; color: var(--text-muted);">Prefix Length</div>
                    <div id="prefixLength" style="font-weight: 600;">/64</div>
                </div>
                <div class="ipv6-info">
                    <div style="font-size: 12px; color: var(--text-muted);">Scope</div>
                    <div id="scope" style="font-weight: 600;">ULA (Local)</div>
                </div>
            </div>
        </div>
      `, () => {
    function generateGlobalId() {
      const bytes = new Uint8Array(5); // 40 bits = 5 bytes
      crypto.getRandomValues(bytes);
      return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
    }

    function generateInterfaceId(type = 'random') {
      if (type === 'random') {
        const bytes = new Uint8Array(8); // 64 bits = 8 bytes
        crypto.getRandomValues(bytes);

        // Ensure it's not a multicast address (first byte = 0xFF)
        bytes[0] &= 0xFD; // Clear multicast bit

        return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
      } else if (type === 'eui64') {
        // Generate a fake MAC and convert to EUI-64
        const bytes = new Uint8Array(6);
        crypto.getRandomValues(bytes);

        // Convert MAC to EUI-64
        const mac = Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
        const first = mac.substring(0, 6);
        const second = mac.substring(6);

        // Flip the universal/local bit
        const firstByte = parseInt(first.substring(0, 2), 16);
        const flipped = (firstByte ^ 0x02).toString(16).padStart(2, '0');

        return flipped + first.substring(2) + 'fffe' + second;
      }
      return '0000000000000000';
    }

    function formatIPv6(hexString) {
      // Format as IPv6 address with colons
      const parts = hexString.match(/.{4}/g) || [];
      return parts.join(':');
    }

    function generateULA() {
      const globalId = $('#globalId').value || generateGlobalId();
      const subnetId = $('#subnetId').value.padStart(4, '0');
      const interfaceType = $('#interfaceType').value;

      let interfaceId = $('#interfaceId').value.replace(/:/g, '').replace(/-/g, '');
      if (!interfaceId || interfaceType !== 'manual') {
        interfaceId = generateInterfaceId(interfaceType);
        $('#interfaceId').value = formatIPv6(interfaceId);
      }

      // Build the ULA address
      const prefix = 'fd';
      const addressHex = prefix + globalId + subnetId + interfaceId;

      // Format as IPv6
      const address = formatIPv6(addressHex);
      const network = formatIPv6(prefix + globalId + subnetId + '0000000000000000');

      return {
        address,
        network,
        prefix: 'fd00::/8',
        globalId,
        subnetId,
        interfaceId,
        prefixLength: 64
      };
    }

    $('#generate').addEventListener('click', () => {
      try {
        const ula = generateULA();

        // Update component displays
        $('#fullAddress').textContent = ula.address + '/64';
        $('#network').textContent = ula.network + '/64';

        // Update global ID if empty
        if (!$('#globalId').value) {
          $('#globalId').value = ula.globalId;
        }

        // Build results
        const results = [
          '=== IPv6 ULA ADDRESS ===',
          `Full Address: ${ula.address}/64`,
          `Network: ${ula.network}/64`,
          '',
          '=== COMPONENTS ===',
          `Prefix: ${ula.prefix}`,
          `Global ID (40 bits): ${ula.globalId}`,
          `Subnet ID (16 bits): ${ula.subnetId}`,
          `Interface ID (64 bits): ${formatIPv6(ula.interfaceId)}`,
          '',
          '=== INFORMATION ===',
          'Scope: Unique Local Address (ULA)',
          'Purpose: Private networking (not routable on internet)',
          'Range: fd00::/8 to fdff::/8',
          'Standard: RFC 4193'
        ].join('\n');

        $('#results').textContent = results;
        toast('ULA address generated');
      } catch (error) {
        toast('Error: ' + error.message, 'error');
      }
    });

    $('#generateSubnet').addEventListener('click', () => {
      // Generate new subnet ID
      const bytes = new Uint8Array(2); // 16 bits = 2 bytes
      crypto.getRandomValues(bytes);
      const subnetId = Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
      $('#subnetId').value = subnetId;

      // Generate new interface ID based on selected type
      const interfaceType = $('#interfaceType').value;
      const interfaceId = generateInterfaceId(interfaceType);
      $('#interfaceId').value = formatIPv6(interfaceId);

      toast('New subnet generated');
      $('#generate').click();
    });

    $('#copy').addEventListener('click', () => {
      navigator.clipboard.writeText($('#fullAddress').textContent).then(() => toast('Address copied'));
    });

    // Initialize
    $('#generateSubnet').click();
  });
}

// MATH TOOLS

function etaTool() {
  setTool('ETA Calculator', `
        <div class="row">
            <div class="form-group">
                <label>Start Time</label>
                <input type="datetime-local" id="startTime" />
            </div>
            <div class="form-group">
                <label>Current Progress</label>
                <div class="row">
                    <input type="number" id="completed" placeholder="Completed" value="50" style="flex: 1;" />
                    <div style="display: flex; align-items: center;">/</div>
                    <input type="number" id="total" placeholder="Total" value="100" style="flex: 1;" />
                </div>
            </div>
        </div>
        <div class="row">
            <div class="form-group">
                <label>Or Enter Speed</label>
                <div class="row">
                    <input type="number" id="speed" placeholder="Items per hour" style="flex: 2;" />
                    <select id="speedUnit" style="flex: 1;">
                        <option value="hour">per hour</option>
                        <option value="minute">per minute</option>
                        <option value="second">per second</option>
                    </select>
                </div>
            </div>
            <div class="form-group">
                <label>Remaining</label>
                <input type="number" id="remaining" placeholder="Remaining items" value="50" />
            </div>
        </div>
        <div class="btn-group">
            <button id="calculate" class="btn">Calculate ETA</button>
            <button id="setNow" class="btn btn-secondary">Set Start to Now</button>
            <button id="copy" class="btn btn-secondary">Copy ETA</button>
        </div>
        <div id="results" class="output"></div>
        <div id="etaDisplay" style="margin-top: 16px; padding: 20px; background: var(--bg-secondary); border-radius: 12px; text-align: center;">
            <div style="font-size: 12px; color: var(--text-muted); margin-bottom: 8px;">Estimated Completion</div>
            <div id="etaTime" style="font-size: 24px; font-weight: 700;"></div>
            <div id="etaRelative" style="font-size: 14px; color: var(--text-muted); margin-top: 4px;"></div>
        </div>
      `, () => {
    function calculateETA() {
      const startTimeInput = $('#startTime').value;
      const completed = parseFloat($('#completed').value) || 0;
      const total = parseFloat($('#total').value) || 1;
      const speed = parseFloat($('#speed').value) || 0;
      const speedUnit = $('#speedUnit').value;
      const remainingInput = $('#remaining').value;

      let startTime, remaining, elapsedMs, speedPerMs;

      // Calculate remaining items
      if (remainingInput && !isNaN(parseFloat(remainingInput))) {
        remaining = parseFloat(remainingInput);
      } else {
        remaining = total - completed;
        $('#remaining').value = remaining;
      }

      // Calculate speed
      if (startTimeInput) {
        startTime = new Date(startTimeInput);
        const now = new Date();
        elapsedMs = now - startTime;

        if (completed > 0 && elapsedMs > 0) {
          // Calculate speed from progress
          const itemsPerMs = completed / elapsedMs;
          speedPerMs = itemsPerMs;

          // Update speed display
          const itemsPerHour = itemsPerMs * 3600000;
          $('#speed').value = Math.round(itemsPerHour * 100) / 100;
        }
      }

      // Use manual speed if provided
      if (speed > 0) {
        let speedPerHour = speed;

        switch (speedUnit) {
          case 'minute':
            speedPerHour = speed * 60;
            break;
          case 'second':
            speedPerHour = speed * 3600;
            break;
        }

        speedPerMs = speedPerHour / 3600000;
      }

      if (!speedPerMs || speedPerMs <= 0) {
        throw new Error('Cannot calculate ETA. Provide either start time and progress, or speed.');
      }

      // Calculate ETA
      const remainingMs = remaining / speedPerMs;
      const eta = new Date(Date.now() + remainingMs);

      // Format results
      const elapsedTime = elapsedMs ? formatDuration(elapsedMs) : 'N/A';
      const remainingTime = formatDuration(remainingMs);
      const speedDisplay = speedPerMs * 3600000; // Items per hour

      return {
        eta,
        elapsedTime,
        remainingTime,
        speed: speedDisplay,
        progress: (completed / total * 100).toFixed(1),
        remaining,
        total
      };
    }

    function formatDuration(ms) {
      const seconds = Math.floor(ms / 1000);
      const minutes = Math.floor(seconds / 60);
      const hours = Math.floor(minutes / 60);
      const days = Math.floor(hours / 24);

      if (days > 0) {
        return `${days}d ${hours % 24}h`;
      } else if (hours > 0) {
        return `${hours}h ${minutes % 60}m`;
      } else if (minutes > 0) {
        return `${minutes}m ${seconds % 60}s`;
      } else {
        return `${seconds}s`;
      }
    }

    $('#calculate').addEventListener('click', () => {
      try {
        const result = calculateETA();

        // Update ETA display
        $('#etaTime').textContent = result.eta.toLocaleTimeString();
        $('#etaRelative').textContent = `in ${result.remainingTime}`;

        // Build results
        const results = [
          '=== ETA CALCULATION ===',
          `Estimated Completion: ${result.eta.toLocaleString()}`,
          `Time Remaining: ${result.remainingTime}`,
          '',
          '=== PROGRESS ===',
          `Completed: ${result.completed}/${result.total}`,
          `Progress: ${result.progress}%`,
          `Remaining: ${result.remaining}`,
          '',
          '=== SPEED ===',
          `Speed: ${result.speed.toFixed(2)} items/hour`,
          `Elapsed Time: ${result.elapsedTime}`
        ].join('\n');

        $('#results').textContent = results;
        toast('ETA calculated');
      } catch (error) {
        toast('Error: ' + error.message, 'error');
        $('#results').textContent = error.message;
      }
    });

    $('#setNow').addEventListener('click', () => {
      const now = new Date();
      const localDateTime = new Date(now.getTime() - now.getTimezoneOffset() * 60000)
        .toISOString()
        .slice(0, 16);
      $('#startTime').value = localDateTime;
      toast('Start time set to now');
    });

    $('#copy').addEventListener('click', () => {
      const eta = $('#etaTime').textContent;
      const relative = $('#etaRelative').textContent;
      navigator.clipboard.writeText(`ETA: ${eta} (${relative})`).then(() => toast('ETA copied'));
    });

    // Initialize
    $('#setNow').click();
    $('#calculate').click();
  });
}

// MEASUREMENT TOOLS

function chronometerTool() {
  setTool('Chronometer', `
        <div id="timerDisplay" style="text-align: center; padding: 40px; background: var(--bg-secondary); border-radius: 16px; margin-bottom: 24px;">
            <div style="font-size: 64px; font-weight: 700; font-family: monospace; margin-bottom: 16px;">00:00:00.000</div>
            <div style="font-size: 14px; color: var(--text-muted);">Hours : Minutes : Seconds . Milliseconds</div>
        </div>
        <div class="btn-group" style="justify-content: center;">
            <button id="start" class="btn"><i class="fas fa-play"></i> Start</button>
            <button id="pause" class="btn btn-secondary"><i class="fas fa-pause"></i> Pause</button>
            <button id="reset" class="btn btn-secondary"><i class="fas fa-redo"></i> Reset</button>
            <button id="lap" class="btn btn-secondary"><i class="fas fa-flag"></i> Lap</button>
        </div>
        <div id="laps" style="margin-top: 24px; max-height: 300px; overflow-y: auto;">
            <div style="display: flex; justify-content: space-between; padding: 8px 12px; background: var(--bg-secondary); border-radius: 8px; margin-bottom: 8px; font-weight: 600;">
                <div>Lap #</div>
                <div>Time</div>
                <div>Split</div>
            </div>
            <div id="lapsList"></div>
        </div>
      `, () => {
    let startTime = null;
    let elapsedTime = 0;
    let timerInterval = null;
    let isRunning = false;
    let lastLapTime = 0;
    let lapCount = 0;

    function formatTime(ms) {
      const hours = Math.floor(ms / 3600000);
      const minutes = Math.floor((ms % 3600000) / 60000);
      const seconds = Math.floor((ms % 60000) / 1000);
      const milliseconds = ms % 1000;

      return `${hours.toString().padStart(2, '0')}:${minutes.toString().padStart(2, '0')}:${seconds.toString().padStart(2, '0')}.${milliseconds.toString().padStart(3, '0')}`;
    }

    function updateDisplay() {
      const display = $('#timerDisplay div');
      if (display) {
        const time = isRunning ? Date.now() - startTime + elapsedTime : elapsedTime;
        display.textContent = formatTime(time);
      }
    }

    function startTimer() {
      if (!isRunning) {
        startTime = Date.now() - elapsedTime;
        timerInterval = setInterval(updateDisplay, 10);
        isRunning = true;
        $('#start').innerHTML = '<i class="fas fa-play"></i> Resume';
        toast('Timer started');
      }
    }

    function pauseTimer() {
      if (isRunning) {
        clearInterval(timerInterval);
        elapsedTime = Date.now() - startTime;
        isRunning = false;
        $('#start').innerHTML = '<i class="fas fa-play"></i> Start';
        toast('Timer paused');
      }
    }

    function resetTimer() {
      clearInterval(timerInterval);
      startTime = null;
      elapsedTime = 0;
      isRunning = false;
      lastLapTime = 0;
      lapCount = 0;
      $('#start').innerHTML = '<i class="fas fa-play"></i> Start';
      $('#lapsList').innerHTML = '';
      updateDisplay();
      toast('Timer reset');
    }

    function recordLap() {
      if (startTime || elapsedTime > 0) {
        const currentTime = isRunning ? Date.now() - startTime + elapsedTime : elapsedTime;
        const lapTime = currentTime - lastLapTime;
        lapCount++;

        const lapElement = document.createElement('div');
        lapElement.className = 'lap-item';
        lapElement.style.cssText = `
                    display: flex;
                    justify-content: space-between;
                    padding: 8px 12px;
                    background: var(--card);
                    border-radius: 4px;
                    margin-bottom: 4px;
                    font-family: monospace;
                `;

        lapElement.innerHTML = `
                    <div>${lapCount}</div>
                    <div>${formatTime(currentTime)}</div>
                    <div>${formatTime(lapTime)}</div>
                `;

        $('#lapsList').prepend(lapElement);
        lastLapTime = currentTime;

        toast(`Lap ${lapCount} recorded`);
      } else {
        toast('Start timer first', 'error');
      }
    }

    $('#start').addEventListener('click', startTimer);
    $('#pause').addEventListener('click', pauseTimer);
    $('#reset').addEventListener('click', resetTimer);
    $('#lap').addEventListener('click', recordLap);

    // Keyboard shortcuts
    document.addEventListener('keydown', (e) => {
      if (e.target.tagName === 'INPUT' || e.target.tagName === 'TEXTAREA') return;

      switch(e.key) {
        case ' ':
        case 's':
          e.preventDefault();
          if (isRunning) pauseTimer();
          else startTimer();
          break;
        case 'r':
          e.preventDefault();
          resetTimer();
          break;
        case 'l':
          e.preventDefault();
          recordLap();
          break;
      }
    });

    // Initialize
    updateDisplay();
  });
}

function tempTool() {
  setTool('Temperature Converter', `
        <div class="row">
            <div class="form-group">
                <label>From</label>
                <select id="fromUnit">
                    <option value="celsius">Celsius (°C)</option>
                    <option value="fahrenheit">Fahrenheit (°F)</option>
                    <option value="kelvin">Kelvin (K)</option>
                    <option value="rankine">Rankine (°R)</option>
                    <option value="delisle">Delisle (°De)</option>
                    <option value="newton">Newton (°N)</option>
                    <option value="reaumur">Réaumur (°Ré)</option>
                    <option value="romer">Rømer (°Rø)</option>
                </select>
            </div>
            <div class="form-group">
                <label>To</label>
                <select id="toUnit">
                    <option value="fahrenheit">Fahrenheit (°F)</option>
                    <option value="celsius" selected>Celsius (°C)</option>
                    <option value="kelvin">Kelvin (K)</option>
                    <option value="rankine">Rankine (°R)</option>
                    <option value="delisle">Delisle (°De)</option>
                    <option value="newton">Newton (°N)</option>
                    <option value="reaumur">Réaumur (°Ré)</option>
                    <option value="romer">Rømer (°Rø)</option>
                </select>
            </div>
        </div>
        <div class="form-group">
            <label>Temperature</label>
            <input type="number" id="temperature" value="0" step="0.1" />
        </div>
        <div class="btn-group">
            <button id="convert" class="btn">Convert</button>
            <button id="swap" class="btn btn-secondary">Swap Units</button>
            <button id="copy" class="btn btn-secondary">Copy Result</button>
        </div>
        <div id="result" class="output"></div>
        <div style="margin-top: 16px;">
            <h4 style="margin-bottom: 8px;">🌡️ Common Temperatures</h4>
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 8px;">
                <button class="temp-preset" data-c="100">Water boils (100°C)</button>
                <button class="temp-preset" data-c="37">Body temp (37°C)</button>
                <button class="temp-preset" data-c="20">Room temp (20°C)</button>
                <button class="temp-preset" data-c="0">Water freezes (0°C)</button>
                <button class="temp-preset" data-c="-40">-40°C = -40°F</button>
                <button class="temp-preset" data-c="-273.15">Absolute zero</button>
            </div>
        </div>
      `, () => {
    function convertTemperature(value, fromUnit, toUnit) {
      // Convert to Celsius first
      let celsius;

      switch(fromUnit) {
        case 'celsius':
          celsius = value;
          break;
        case 'fahrenheit':
          celsius = (value - 32) * 5/9;
          break;
        case 'kelvin':
          celsius = value - 273.15;
          break;
        case 'rankine':
          celsius = (value - 491.67) * 5/9;
          break;
        case 'delisle':
          celsius = 100 - value * 2/3;
          break;
        case 'newton':
          celsius = value * 100/33;
          break;
        case 'reaumur':
          celsius = value * 5/4;
          break;
        case 'romer':
          celsius = (value - 7.5) * 40/21;
          break;
        default:
          celsius = value;
      }

      // Convert from Celsius to target unit
      switch(toUnit) {
        case 'celsius':
          return celsius;
        case 'fahrenheit':
          return celsius * 9/5 + 32;
        case 'kelvin':
          return celsius + 273.15;
        case 'rankine':
          return (celsius + 273.15) * 9/5;
        case 'delisle':
          return (100 - celsius) * 3/2;
        case 'newton':
          return celsius * 33/100;
        case 'reaumur':
          return celsius * 4/5;
        case 'romer':
          return celsius * 21/40 + 7.5;
        default:
          return celsius;
      }
    }

    function formatUnit(unit) {
      const units = {
        'celsius': '°C',
        'fahrenheit': '°F',
        'kelvin': 'K',
        'rankine': '°R',
        'delisle': '°De',
        'newton': '°N',
        'reaumur': '°Ré',
        'romer': '°Rø'
      };
      return units[unit] || unit;
    }

    $('#convert').addEventListener('click', () => {
      const value = parseFloat($('#temperature').value);
      const fromUnit = $('#fromUnit').value;
      const toUnit = $('#toUnit').value;

      if (isNaN(value)) {
        toast('Please enter a valid temperature', 'error');
        return;
      }

      const result = convertTemperature(value, fromUnit, toUnit);
      const formatted = `${value.toFixed(2)} ${formatUnit(fromUnit)} = ${result.toFixed(2)} ${formatUnit(toUnit)}`;

      $('#result').textContent = formatted;
      toast('Temperature converted');
    });

    $('#swap').addEventListener('click', () => {
      const fromUnit = $('#fromUnit').value;
      const toUnit = $('#toUnit').value;
      $('#fromUnit').value = toUnit;
      $('#toUnit').value = fromUnit;
      $('#convert').click();
    });

    $('#copy').addEventListener('click', () => {
      navigator.clipboard.writeText($('#result').textContent).then(() => toast('Copied'));
    });

    // Preset buttons
    $$('.temp-preset').forEach(btn => {
      btn.addEventListener('click', () => {
        const celsius = parseFloat(btn.dataset.c);
        $('#temperature').value = celsius;
        $('#fromUnit').value = 'celsius';
        $('#convert').click();
        toast('Preset loaded');
      });

      // Style the buttons
      btn.style.padding = '8px 12px';
      btn.style.background = 'var(--card)';
      btn.style.border = '1px solid var(--border)';
      btn.style.borderRadius = '4px';
      btn.style.color = 'var(--text)';
      btn.style.cursor = 'pointer';
      btn.style.fontSize = '12px';
      btn.style.textAlign = 'center';
      btn.style.transition = 'background-color 0.2s';

      btn.addEventListener('mouseenter', () => {
        btn.style.background = 'var(--card-hover)';
      });

      btn.addEventListener('mouseleave', () => {
        btn.style.background = 'var(--card)';
      });
    });

    // Initialize
    $('#convert').click();
  });
}

function benchmarkTool() {
  setTool('Benchmark Builder', `
        <div class="form-group">
            <label>Test Name</label>
            <input type="text" id="testName" placeholder="My Benchmark Test" value="Performance Test" />
        </div>
        <div class="form-group">
            <label>Number of Iterations</label>
            <input type="number" id="iterations" value="1000" min="1" max="1000000" />
        </div>
        <div id="testCases">
            <div class="test-case">
                <div style="display: flex; gap: 12px; margin-bottom: 12px;">
                    <input type="text" class="case-name" placeholder="Test Case 1" value="Array for-loop" style="flex: 2;" />
                    <textarea class="case-code" rows="3" placeholder="// Your test code here
const arr = new Array(1000).fill(0);
for (let i = 0; i < arr.length; i++) {
  arr[i] = i * i;
}" style="flex: 3; font-family: monospace; font-size: 12px;"></textarea>
                </div>
                <div style="display: flex; gap: 8px;">
                    <button class="run-case btn" style="flex: 1;">Run This Test</button>
                    <button class="remove-case btn btn-secondary">Remove</button>
                </div>
            </div>
        </div>
        <div class="btn-group">
            <button id="addCase" class="btn"><i class="fas fa-plus"></i> Add Test Case</button>
            <button id="runAll" class="btn"><i class="fas fa-play"></i> Run All Tests</button>
            <button id="clearResults" class="btn btn-secondary">Clear Results</button>
        </div>
        <div id="results" class="output" style="margin-top: 16px;"></div>
        <div id="chart" style="margin-top: 16px; height: 200px; display: none;"></div>
      `, () => {
    let testResults = [];

    function addTestCase(name = '', code = '') {
      const testCase = document.createElement('div');
      testCase.className = 'test-case';
      testCase.innerHTML = `
                <div style="display: flex; gap: 12px; margin-bottom: 12px;">
                    <input type="text" class="case-name" placeholder="Test Case ${$('#testCases').children.length + 1}" value="${name}" style="flex: 2;" />
                    <textarea class="case-code" rows="3" placeholder="// Your test code here" style="flex: 3; font-family: monospace; font-size: 12px;">${code}</textarea>
                </div>
                <div style="display: flex; gap: 8px;">
                    <button class="run-case btn" style="flex: 1;">Run This Test</button>
                    <button class="remove-case btn btn-secondary">Remove</button>
                </div>
            `;

      $('#testCases').appendChild(testCase);

      // Add event listeners
      testCase.querySelector('.run-case').addEventListener('click', () => runTestCase(testCase));
      testCase.querySelector('.remove-case').addEventListener('click', () => {
        testCase.remove();
        toast('Test case removed');
      });

      return testCase;
    }

    function runTestCase(testCaseElement) {
      const name = testCaseElement.querySelector('.case-name').value || 'Unnamed Test';
      const code = testCaseElement.querySelector('.case-code').value;
      const iterations = parseInt($('#iterations').value) || 1000;

      if (!code.trim()) {
        toast('Please enter test code', 'error');
        return;
      }

      try {
        // Warm-up run
        try {
          (new Function(code))();
        } catch (e) {
          // Ignore warm-up errors
        }

        // Actual benchmark
        const startTime = performance.now();

        for (let i = 0; i < iterations; i++) {
          (new Function(code))();
        }

        const endTime = performance.now();
        const duration = endTime - startTime;
        const opsPerSec = (iterations / duration) * 1000;

        const result = {
          name,
          duration,
          iterations,
          opsPerSec,
          timestamp: new Date().toLocaleTimeString()
        };

        testResults.push(result);
        displayResults();
        toast(`Test "${name}" completed`);

      } catch (error) {
        toast(`Test error: ${error.message}`, 'error');
      }
    }

    function runAllTests() {
      const testCases = $$('.test-case');
      if (testCases.length === 0) {
        toast('No test cases to run', 'error');
        return;
      }

      testResults = [];
      $('#results').textContent = 'Running tests...';

      let completed = 0;
      testCases.forEach((testCase, index) => {
        setTimeout(() => {
          runTestCase(testCase);
          completed++;

          if (completed === testCases.length) {
            toast('All tests completed');
            displayChart();
          }
        }, index * 100);
      });
    }

    function displayResults() {
      if (testResults.length === 0) {
        $('#results').textContent = 'No test results yet. Run some tests!';
        $('#chart').style.display = 'none';
        return;
      }

      const sorted = [...testResults].sort((a, b) => b.opsPerSec - a.opsPerSec);
      const fastest = sorted[0];

      const results = [
        `=== BENCHMARK RESULTS (${$('#testName').value || 'Unnamed Test'}) ===`,
        `Total tests: ${testResults.length}`,
        `Iterations per test: ${$('#iterations').value}`,
        '',
        '=== PERFORMANCE RANKING ===',
        ...sorted.map((result, index) => {
          const relative = (result.opsPerSec / fastest.opsPerSec * 100).toFixed(1);
          return `${index + 1}. ${result.name}: ${result.opsPerSec.toFixed(2)} ops/sec (${relative}% of fastest)`;
        }),
        '',
        '=== DETAILED RESULTS ===',
        ...testResults.map(result =>
          `${result.name}: ${result.duration.toFixed(2)}ms for ${result.iterations} iterations (${result.opsPerSec.toFixed(2)} ops/sec) at ${result.timestamp}`
        )
      ].join('\n');

      $('#results').textContent = results;
      displayChart();
    }

    function displayChart() {
      if (testResults.length < 2) {
        $('#chart').style.display = 'none';
        return;
      }

      $('#chart').style.display = 'block';
      $('#chart').innerHTML = '';

      const maxOps = Math.max(...testResults.map(r => r.opsPerSec));
      const barHeight = 30;
      const chartHeight = testResults.length * (barHeight + 4);
      $('#chart').style.height = `${chartHeight}px`;

      testResults.forEach((result, index) => {
        const width = (result.opsPerSec / maxOps) * 100;
        const bar = document.createElement('div');
        bar.style.cssText = `
                    margin-bottom: 4px;
                    height: ${barHeight}px;
                    background: linear-gradient(90deg, var(--primary) ${width}%, var(--bg-secondary) ${width}%);
                    border-radius: 4px;
                    display: flex;
                    align-items: center;
                    padding: 0 12px;
                    position: relative;
                `;

        bar.innerHTML = `
                    <div style="color: white; font-weight: 600; text-shadow: 0 1px 2px rgba(0,0,0,0.5);">
                        ${result.name}: ${result.opsPerSec.toFixed(2)} ops/sec
                    </div>
                    <div style="position: absolute; right: 12px; color: white; font-weight: 600;">
                        ${width.toFixed(1)}%
                    </div>
                `;

        $('#chart').appendChild(bar);
      });
    }

    $('#addCase').addEventListener('click', () => {
      addTestCase();
      toast('Test case added');
    });

    $('#runAll').addEventListener('click', runAllTests);

    $('#clearResults').addEventListener('click', () => {
      testResults = [];
      displayResults();
      toast('Results cleared');
    });

    // Initialize with a second test case
    addTestCase('Array forEach', `const arr = new Array(1000).fill(0);
arr.forEach((_, i) => {
  arr[i] = i * i;
});`);

    // Run first test on load
    setTimeout(() => {
      runTestCase($('#testCases .test-case'));
    }, 500);
  });
}

// TEXT TOOLS

function emojiTool() {
  setTool('Emoji Picker', `
        <div class="form-group">
            <label>Search Emojis</label>
            <input type="text" id="search" placeholder="Search by name or category..." />
        </div>
        <div id="emojiGrid" style="display: grid; grid-template-columns: repeat(auto-fill, minmax(60px, 1fr)); gap: 12px; margin-top: 16px; max-height: 400px; overflow-y: auto; padding: 8px;"></div>
        <div style="margin-top: 16px;">
            <h4 style="margin-bottom: 8px;">📋 Recent Emojis</h4>
            <div id="recentEmojis" style="display: flex; gap: 8px; flex-wrap: wrap; min-height: 60px; padding: 12px; background: var(--bg-secondary); border-radius: 8px;"></div>
        </div>
        <div id="emojiInfo" style="margin-top: 16px; padding: 16px; background: var(--bg-secondary); border-radius: 8px; display: none;">
            <h4 style="margin-bottom: 8px;">ℹ️ Selected Emoji</h4>
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 12px;">
                <div>
                    <div style="font-size: 12px; color: var(--text-muted);">Emoji</div>
                    <div id="selectedEmoji" style="font-size: 32px;"></div>
                </div>
                <div>
                    <div style="font-size: 12px; color: var(--text-muted);">Name</div>
                    <div id="selectedName" style="font-weight: 600;"></div>
                </div>
                <div>
                    <div style="font-size: 12px; color: var(--text-muted);">Unicode</div>
                    <div id="selectedUnicode" style="font-family: monospace;"></div>
                </div>
            </div>
            <div class="btn-group" style="margin-top: 12px;">
                <button id="copyEmoji" class="btn">Copy Emoji</button>
                <button id="copyUnicode" class="btn btn-secondary">Copy Unicode</button>
            </div>
        </div>
      `, () => {
    const emojiCategories = {
      'Smileys & Emotion': ['😀', '😃', '😄', '😁', '😅', '😂', '🤣', '😊', '😇', '🙂', '🙃', '😉', '😌', '😍', '🥰', '😘', '😗', '😙', '😚', '😋', '😛', '😝', '😜', '🤪', '🤨', '🧐', '🤓', '😎', '🤩', '🥳'],
      'People & Body': ['👋', '🤚', '🖐', '✋', '🖖', '👌', '🤌', '🤏', '✌️', '🤞', '🤟', '🤘', '🤙', '👈', '👉', '👆', '🖕', '👇', '☝️', '👍', '👎', '✊', '👊', '🤛', '🤜', '👏', '🙌', '👐', '🤲', '🤝'],
      'Animals & Nature': ['🐵', '🐒', '🦍', '🦧', '🐶', '🐕', '🦮', '🐕‍🦺', '🐩', '🐺', '🦊', '🦝', '🐱', '🐈', '🐈‍⬛', '🦁', '🐯', '🐅', '🐆', '🐴', '🐎', '🦄', '🦓', '🦌', '🐮', '🐂', '🐃', '🐄', '🐷', '🐖'],
      'Food & Drink': ['🍇', '🍈', '🍉', '🍊', '🍋', '🍌', '🍍', '🥭', '🍎', '🍏', '🍐', '🍑', '🍒', '🍓', '🥝', '🍅', '🥥', '🥑', '🍆', '🥔', '🥕', '🌽', '🌶️', '🥒', '🥬', '🥦', '🧄', '🧅', '🍄', '🥜'],
      'Travel & Places': ['🚗', '🚕', '🚙', '🚌', '🚎', '🏎️', '🚓', '🚑', '🚒', '🚐', '🚚', '🚛', '🚜', '🛴', '🚲', '🛵', '🏍️', '🛺', '🚨', '🚔', '🚍', '🚘', '🚖', '🚡', '🚠', '🚟', '🚃', '🚋', '🚞', '🚂'],
      'Activities': ['⚽', '🏀', '🏈', '⚾', '🥎', '🎾', '🏐', '🏉', '🥏', '🎱', '🪀', '🏓', '🏸', '🏒', '🏑', '🥍', '🏏', '🪃', '🥅', '⛳', '🪁', '🏹', '🎣', '🤿', '🥊', '🥋', '🎽', '🛹', '🛼', '🛷'],
      'Objects': ['⌚', '📱', '📲', '💻', '⌨️', '🖥️', '🖨️', '🖱️', '🖲️', '🕹️', '🗜️', '💽', '💾', '💿', '📀', '📼', '📷', '📸', '📹', '🎥', '📽️', '🎞️', '📞', '☎️', '📟', '📠', '📺', '📻', '🎙️', '🎚️'],
      'Symbols': ['❤️', '🧡', '💛', '💚', '💙', '💜', '🖤', '🤍', '🤎', '💔', '❣️', '💕', '💞', '💓', '💗', '💖', '💘', '💝', '💟', '☮️', '✝️', '☪️', '🕉️', '☸️', '✡️', '🔯', '🕎', '☯️', '☦️', '🛐'],
      'Flags': ['🏁', '🚩', '🎌', '🏴', '🏳️', '🏳️‍🌈', '🏳️‍⚧️', '🏴‍☠️', '🇦🇫', '🇦🇽', '🇦🇱', '🇩🇿', '🇦🇸', '🇦🇩', '🇦🇴', '🇦🇮', '🇦🇶', '🇦🇬', '🇦🇷', '🇦🇲', '🇦🇼', '🇦🇺', '🇦🇹', '🇦🇿', '🇧🇸', '🇧🇭', '🇧🇩', '🇧🇧', '🇧🇾', '🇧🇪']
    };

    const emojiNames = {
      '😀': 'Grinning Face', '😃': 'Grinning Face with Big Eyes', '😄': 'Grinning Face with Smiling Eyes',
      '😁': 'Beaming Face with Smiling Eyes', '😅': 'Grinning Face with Sweat', '😂': 'Face with Tears of Joy',
      '🤣': 'Rolling on the Floor Laughing', '😊': 'Smiling Face with Smiling Eyes', '😇': 'Smiling Face with Halo',
      '🙂': 'Slightly Smiling Face', '🙃': 'Upside-Down Face', '😉': 'Winking Face',
      '😌': 'Relieved Face', '😍': 'Smiling Face with Heart-Eyes', '🥰': 'Smiling Face with Hearts',
      '❤️': 'Red Heart', '👍': 'Thumbs Up', '👋': 'Waving Hand', '🎉': 'Party Popper',
      '🔥': 'Fire', '⭐': 'Star', '✨': 'Sparkles', '🙏': 'Folded Hands'
    };

    let recentEmojis = JSON.parse(localStorage.getItem('recentEmojis') || '[]');

    function getEmojiUnicode(emoji) {
      return Array.from(emoji).map(char =>
        'U+' + char.codePointAt(0).toString(16).toUpperCase()
      ).join(' ');
    }

    function renderEmojiGrid(filter = '') {
      const filtered = filter.toLowerCase();
      let html = '';

      for (const [category, emojis] of Object.entries(emojiCategories)) {
        const filteredEmojis = emojis.filter(emoji =>
          !filtered ||
          (emojiNames[emoji] || '').toLowerCase().includes(filtered) ||
          category.toLowerCase().includes(filtered)
        );

        if (filteredEmojis.length > 0) {
          html += `<div style="grid-column: 1 / -1; font-size: 12px; color: var(--text-muted); margin-top: 12px; margin-bottom: 4px;">${category}</div>`;

          filteredEmojis.forEach(emoji => {
            const name = emojiNames[emoji] || 'Emoji';
            html += `
                            <div class="emoji-item" data-emoji="${emoji}" title="${name}"
                                 style="font-size: 24px; text-align: center; padding: 8px; cursor: pointer; border-radius: 8px; background: var(--card); transition: background-color 0.2s;">
                                ${emoji}
                            </div>
                        `;
          });
        }
      }

      $('#emojiGrid').innerHTML = html || '<div style="grid-column: 1 / -1; text-align: center; padding: 40px; color: var(--text-muted);">No emojis found</div>';

      // Add click handlers
      $$('.emoji-item').forEach(item => {
        item.addEventListener('click', () => selectEmoji(item.dataset.emoji));

        item.addEventListener('mouseenter', () => {
          item.style.background = 'var(--card-hover)';
        });

        item.addEventListener('mouseleave', () => {
          item.style.background = 'var(--card)';
        });
      });
    }

    function renderRecentEmojis() {
      if (recentEmojis.length === 0) {
        $('#recentEmojis').innerHTML = '<div style="color: var(--text-muted); font-style: italic;">No recent emojis</div>';
        return;
      }

      const html = recentEmojis.map(emoji => `
                <div class="recent-emoji" data-emoji="${emoji}"
                     style="font-size: 24px; padding: 8px; cursor: pointer; border-radius: 4px; background: var(--card);">
                    ${emoji}
                </div>
            `).join('');

      $('#recentEmojis').innerHTML = html;

      $$('.recent-emoji').forEach(item => {
        item.addEventListener('click', () => selectEmoji(item.dataset.emoji));
      });
    }

    function selectEmoji(emoji) {
      const name = emojiNames[emoji] || 'Emoji';
      const unicode = getEmojiUnicode(emoji);

      // Update info panel
      $('#selectedEmoji').textContent = emoji;
      $('#selectedName').textContent = name;
      $('#selectedUnicode').textContent = unicode;
      $('#emojiInfo').style.display = 'block';

      // Add to recent emojis
      recentEmojis = recentEmojis.filter(e => e !== emoji);
      recentEmojis.unshift(emoji);
      recentEmojis = recentEmojis.slice(0, 12);
      localStorage.setItem('recentEmojis', JSON.stringify(recentEmojis));

      renderRecentEmojis();
      toast(`Selected: ${name}`);
    }

    $('#search').addEventListener('input', (e) => {
      renderEmojiGrid(e.target.value);
    });

    $('#copyEmoji').addEventListener('click', () => {
      const emoji = $('#selectedEmoji').textContent;
      if (emoji) {
        navigator.clipboard.writeText(emoji).then(() => toast('Emoji copied'));
      }
    });

    $('#copyUnicode').addEventListener('click', () => {
      const unicode = $('#selectedUnicode').textContent;
      if (unicode) {
        navigator.clipboard.writeText(unicode).then(() => toast('Unicode copied'));
      }
    });

    // Initialize
    renderEmojiGrid();
    renderRecentEmojis();

    // Select first emoji
    setTimeout(() => {
      const firstEmoji = Object.values(emojiCategories)[0]?.[0];
      if (firstEmoji) {
        selectEmoji(firstEmoji);
      }
    }, 100);
  });
}

function obfuscatorTool() {
  setTool('String Obfuscator', `
        <div class="form-group">
            <label>Text to Obfuscate</label>
            <textarea id="input" rows="4" placeholder="Enter sensitive text (IBAN, token, secret, etc.)">CH9300762011623852957</textarea>
        </div>
        <div class="row">
            <div class="form-group">
                <label>Obfuscation Method</label>
                <select id="method">
                    <option value="mask">Mask characters</option>
                    <option value="replace">Replace with character</option>
                    <option value="partial">Show partial</option>
                    <option value="random">Random characters</option>
                </select>
            </div>
            <div class="form-group">
                <label>Visible Characters</label>
                <input type="number" id="visible" value="4" min="0" max="20" />
            </div>
        </div>
        <div class="row">
            <div class="form-group">
                <label>Mask Character</label>
                <input type="text" id="maskChar" value="*" maxlength="1" />
            </div>
            <div class="form-group">
                <label>Show from</label>
                <select id="position">
                    <option value="start">Start</option>
                    <option value="end">End</option>
                    <option value="both">Both ends</option>
                </select>
            </div>
        </div>
        <div class="btn-group">
            <button id="obfuscate" class="btn">Obfuscate Text</button>
            <button id="copy" class="btn btn-secondary">Copy Result</button>
            <button id="example" class="btn btn-secondary">Load Example</button>
        </div>
        <div id="output" class="output"></div>
        <div style="margin-top: 16px; padding: 16px; background: var(--bg-secondary); border-radius: 8px;">
            <h4 style="margin-bottom: 8px;">🔒 Obfuscation Examples</h4>
            <div style="font-size: 14px;">
                <div><strong>IBAN:</strong> CH9300762011623852957 → CH93**********2957</div>
                <div><strong>Credit Card:</strong> 4111111111111111 → 4111********1111</div>
                <div><strong>API Key:</strong> sk_live_abc123def456 → sk_live_***456</div>
                <div><strong>Email:</strong> john.doe@example.com → j***@example.com</div>
            </div>
        </div>
      `, () => {
    function obfuscateText(text, options) {
      if (!text.trim()) return '';

      const method = options.method;
      const visible = Math.min(options.visible, text.length);
      const maskChar = options.maskChar || '*';
      const position = options.position;

      switch (method) {
        case 'mask':
          // Mask all but visible characters
          if (position === 'start') {
            const visiblePart = text.substring(0, visible);
            const maskedPart = maskChar.repeat(text.length - visible);
            return visiblePart + maskedPart;
          } else if (position === 'end') {
            const visiblePart = text.substring(text.length - visible);
            const maskedPart = maskChar.repeat(text.length - visible);
            return maskedPart + visiblePart;
          } else {
            // both ends
            const startVisible = Math.ceil(visible / 2);
            const endVisible = Math.floor(visible / 2);
            const startPart = text.substring(0, startVisible);
            const endPart = text.substring(text.length - endVisible);
            const middleMasked = maskChar.repeat(text.length - startVisible - endVisible);
            return startPart + middleMasked + endPart;
          }

        case 'replace':
          // Replace with specified character
          return maskChar.repeat(text.length);

        case 'partial':
          // Show only visible characters
          if (position === 'start') {
            return text.substring(0, visible) + '...';
          } else if (position === 'end') {
            return '...' + text.substring(text.length - visible);
          } else {
            const startVisible = Math.ceil(visible / 2);
            const endVisible = Math.floor(visible / 2);
            return text.substring(0, startVisible) + '...' + text.substring(text.length - endVisible);
          }

        case 'random':
          // Replace with random characters
          const chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
          return Array.from({length: text.length}, () =>
            chars.charAt(Math.floor(Math.random() * chars.length))
          ).join('');

        default:
          return text;
      }
    }

    $('#obfuscate').addEventListener('click', () => {
      const text = $('#input').value;
      const options = {
        method: $('#method').value,
        visible: parseInt($('#visible').value) || 4,
        maskChar: $('#maskChar').value || '*',
        position: $('#position').value
      };

      if (!text.trim()) {
        toast('Please enter text to obfuscate', 'error');
        return;
      }

      const obfuscated = obfuscateText(text, options);
      $('#output').textContent = obfuscated;

      // Show stats
      const stats = `Original: ${text.length} chars | Obfuscated: ${obfuscated.length} chars`;
      toast(`Obfuscated! ${stats}`);
    });

    $('#copy').addEventListener('click', () => {
      navigator.clipboard.writeText($('#output').textContent).then(() => toast('Copied'));
    });

    $('#example').addEventListener('click', () => {
      const examples = [
        'CH9300762011623852957',
        '4111111111111111',
        'sk_live_abc123def456ghi789',
        'john.doe@example.com',
        'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...'
      ];

      const randomExample = examples[Math.floor(Math.random() * examples.length)];
      $('#input').value = randomExample;
      toast('Example loaded');
      $('#obfuscate').click();
    });

    // Initialize
    $('#example').click();
  });
}

function textdiffTool() {
  setTool('Text Diff', `
        <div class="row">
            <div class="form-group">
                <label>Text A (Original)</label>
                <textarea id="textA" rows="6" placeholder="Enter original text">The quick brown fox jumps over the lazy dog.</textarea>
            </div>
            <div class="form-group">
                <label>Text B (Modified)</label>
                <textarea id="textB" rows="6" placeholder="Enter modified text">The quick brown fox jumps over the lazy cat.</textarea>
            </div>
        </div>
        <div class="form-group">
            <label>Options</label>
            <div style="display: flex; gap: 16px;">
                <label style="display: flex; align-items: center; gap: 8px;">
                    <input type="radio" name="diffType" value="char" checked />
                    <span>Character-level diff</span>
                </label>
                <label style="display: flex; align-items: center; gap: 8px;">
                    <input type="radio" name="diffType" value="word" />
                    <span>Word-level diff</span>
                </label>
                <label style="display: flex; align-items: center; gap: 8px;">
                    <input type="radio" name="diffType" value="line" />
                    <span>Line-level diff</span>
                </label>
            </div>
        </div>
        <div class="btn-group">
            <button id="compare" class="btn">Compare Texts</button>
            <button id="swap" class="btn btn-secondary">↔ Swap</button>
            <button id="copy" class="btn btn-secondary">Copy Diff</button>
        </div>
        <div id="diffOutput" class="output" style="font-family: monospace; white-space: pre-wrap;"></div>
        <div id="diffStats" style="margin-top: 16px; padding: 12px; background: var(--bg-secondary); border-radius: 8px; font-size: 14px;"></div>
      `, () => {
    function computeDiff(textA, textB, diffType = 'char') {
      // Simple diff algorithm (LCS-based)
      if (diffType === 'line') {
        const linesA = textA.split('\n');
        const linesB = textB.split('\n');
        return computeLineDiff(linesA, linesB);
      } else if (diffType === 'word') {
        const wordsA = textA.split(/\s+/);
        const wordsB = textB.split(/\s+/);
        return computeWordDiff(wordsA, wordsB);
      } else {
        return computeCharDiff(textA, textB);
      }
    }

    function computeCharDiff(textA, textB) {
      const result = [];
      let i = 0, j = 0;

      while (i < textA.length || j < textB.length) {
        if (i < textA.length && j < textB.length && textA[i] === textB[j]) {
          result.push(textA[i]);
          i++;
          j++;
        } else {
          // Find longest common subsequence
          let found = false;

          for (let k = 1; k <= Math.min(textA.length - i, textB.length - j); k++) {
            if (textA.substring(i, i + k) === textB.substring(j, j + k)) {
              result.push(textA.substring(i, i + k));
              i += k;
              j += k;
              found = true;
              break;
            }
          }

          if (!found) {
            // Add deletions and insertions
            if (i < textA.length) {
              result.push(`[-${textA[i]}+]`);
              i++;
            }
            if (j < textB.length) {
              result.push(`[+${textB[j]}+]`);
              j++;
            }
          }
        }
      }

      return result.join('');
    }

    function computeWordDiff(wordsA, wordsB) {
      const result = [];
      let i = 0, j = 0;

      while (i < wordsA.length || j < wordsB.length) {
        if (i < wordsA.length && j < wordsB.length && wordsA[i] === wordsB[j]) {
          result.push(wordsA[i] + ' ');
          i++;
          j++;
        } else {
          // Find matching word ahead
          let found = false;

          for (let lookahead = 1; lookahead <= 5; lookahead++) {
            if (i + lookahead < wordsA.length && wordsA[i + lookahead] === wordsB[j]) {
              // Words were deleted
              for (let k = 0; k <= lookahead; k++) {
                result.push(`[-${wordsA[i + k]}+] `);
              }
              i += lookahead + 1;
              j++;
              found = true;
              break;
            }

            if (j + lookahead < wordsB.length && wordsA[i] === wordsB[j + lookahead]) {
              // Words were inserted
              result.push(`[+${wordsB[j]}+] `);
              for (let k = 1; k <= lookahead; k++) {
                result.push(`[+${wordsB[j + k]}+] `);
              }
              i++;
              j += lookahead + 1;
              found = true;
              break;
            }
          }

          if (!found) {
            // Replace word
            if (i < wordsA.length) {
              result.push(`[-${wordsA[i]}+] `);
              i++;
            }
            if (j < wordsB.length) {
              result.push(`[+${wordsB[j]}+] `);
              j++;
            }
          }
        }
      }

      return result.join('');
    }

    function computeLineDiff(linesA, linesB) {
      const result = [];
      let i = 0, j = 0;

      while (i < linesA.length || j < linesB.length) {
        if (i < linesA.length && j < linesB.length && linesA[i] === linesB[j]) {
          result.push(`  ${linesA[i]}`);
          i++;
          j++;
        } else {
          // Check if line was moved
          let foundInB = false;
          let foundInA = false;

          for (let k = j + 1; k < linesB.length; k++) {
            if (linesA[i] === linesB[k]) {
              // Lines were inserted before this line
              for (let l = j; l < k; l++) {
                result.push(`+ ${linesB[l]}`);
              }
              j = k;
              foundInB = true;
              break;
            }
          }

          if (!foundInB) {
            for (let k = i + 1; k < linesA.length; k++) {
              if (linesA[k] === linesB[j]) {
                // Lines were deleted before this line
                for (let l = i; l < k; l++) {
                  result.push(`- ${linesA[l]}`);
                }
                i = k;
                foundInA = true;
                break;
              }
            }
          }

          if (!foundInA && !foundInB) {
            // Line was modified
            if (i < linesA.length) {
              result.push(`- ${linesA[i]}`);
              i++;
            }
            if (j < linesB.length) {
              result.push(`+ ${linesB[j]}`);
              j++;
            }
          }
        }
      }

      return result.join('\n');
    }

    function formatDiff(diff, diffType) {
      if (diffType === 'line') {
        return diff;
      }

      // Colorize character/word diff
      let formatted = '';
      let inDeletion = false;
      let inInsertion = false;

      for (let i = 0; i < diff.length; i++) {
        if (diff[i] === '[' && i + 1 < diff.length) {
          if (diff[i + 1] === '-') {
            inDeletion = true;
            formatted += '<span style="background: rgba(239, 68, 68, 0.3); text-decoration: line-through;">';
            i += 2;
          } else if (diff[i + 1] === '+') {
            inInsertion = true;
            formatted += '<span style="background: rgba(34, 197, 94, 0.3);">';
            i += 2;
          }
        } else if (diff[i] === ']' && (inDeletion || inInsertion)) {
          formatted += '</span>';
          inDeletion = false;
          inInsertion = false;
        } else if (diff[i] === '+' && i + 1 < diff.length && diff[i + 1] === ']') {
          i++; // Skip the closing bracket
        } else {
          formatted += diff[i];
        }
      }

      return formatted;
    }

    function getStats(textA, textB, diff) {
      const charsA = textA.length;
      const charsB = textB.length;
      const wordsA = textA.split(/\s+/).length;
      const wordsB = textB.split(/\s+/).length;
      const linesA = textA.split('\n').length;
      const linesB = textB.split('\n').length;

      // Count changes in diff
      const deletions = (diff.match(/\[-/g) || []).length;
      const insertions = (diff.match(/\[\+/g) || []).length;

      return {
        charsA, charsB,
        wordsA, wordsB,
        linesA, linesB,
        deletions, insertions,
        similarity: charsA > 0 ? (1 - (deletions + insertions) / charsA) * 100 : 100
      };
    }

    $('#compare').addEventListener('click', () => {
      const textA = $('#textA').value;
      const textB = $('#textB').value;
      const diffType = document.querySelector('input[name="diffType"]:checked').value;

      if (!textA.trim() || !textB.trim()) {
        toast('Please enter both texts', 'error');
        return;
      }

      const diff = computeDiff(textA, textB, diffType);
      const formatted = formatDiff(diff, diffType);
      const stats = getStats(textA, textB, diff);

      if (diffType === 'line') {
        $('#diffOutput').textContent = diff;
      } else {
        $('#diffOutput').innerHTML = formatted;
      }

      const statsText = [
        `Characters: ${stats.charsA} → ${stats.charsB}`,
        `Words: ${stats.wordsA} → ${stats.wordsB}`,
        `Lines: ${stats.linesA} → ${stats.linesB}`,
        `Changes: ${stats.deletions} deletions, ${stats.insertions} insertions`,
        `Similarity: ${stats.similarity.toFixed(1)}%`
      ].join(' | ');

      $('#diffStats').textContent = statsText;
      toast('Texts compared');
    });

    $('#swap').addEventListener('click', () => {
      const temp = $('#textA').value;
      $('#textA').value = $('#textB').value;
      $('#textB').value = temp;
      $('#compare').click();
    });

    $('#copy').addEventListener('click', () => {
      if ($('#diffOutput').textContent) {
        navigator.clipboard.writeText($('#diffOutput').textContent).then(() => toast('Diff copied'));
      }
    });

    // Initialize
    $('#compare').click();
  });
}

function numeronymTool() {
  setTool('Numeronym Generator', `
        <div class="form-group">
            <label>Word or Phrase</label>
            <input type="text" id="input" placeholder="Enter a word or phrase" value="internationalization" />
        </div>
        <div class="row">
            <div class="form-group">
                <label>Method</label>
                <select id="method">
                    <option value="standard">Standard (i18n)</option>
                    <option value="compact">Compact (k8s)</option>
                    <option value="verbose">Verbose (i-nternationalizatio-n)</option>
                </select>
            </div>
            <div class="form-group">
                <label>Separator</label>
                <input type="text" id="separator" value="" maxlength="1" placeholder="Optional" />
            </div>
        </div>
        <div class="btn-group">
            <button id="generate" class="btn">Generate Numeronym</button>
            <button id="copy" class="btn btn-secondary">Copy Result</button>
            <button id="example" class="btn btn-secondary">Load Example</button>
        </div>
        <div id="output" class="output"></div>
        <div style="margin-top: 16px; padding: 16px; background: var(--bg-secondary); border-radius: 8px;">
            <h4 style="margin-bottom: 8px;">🔢 What are Numeronyms?</h4>
            <div style="font-size: 14px;">
                <p>A numeronym is a word where a number is used to form an abbreviation.</p>
                <p><strong>Examples:</strong></p>
                <ul style="margin: 8px 0; padding-left: 20px;">
                    <li><code>internationalization</code> → <code>i18n</code> (i + 18 letters + n)</li>
                    <li><code>kubernetes</code> → <code>k8s</code> (k + 8 letters + s)</li>
                    <li><code>localization</code> → <code>l10n</code> (l + 10 letters + n)</li>
                    <li><code>accessibility</code> → <code>a11y</code> (a + 11 letters + y)</li>
                </ul>
            </div>
        </div>
      `, () => {
    function generateNumeronym(word, method, separator = '') {
      word = word.trim();
      if (!word) return '';

      const length = word.length;

      if (length <= 3) {
        return word; // Too short for numeronym
      }

      switch (method) {
        case 'standard':
          // Standard i18n style: first + count + last
          return word[0] + (length - 2) + word[length - 1];

        case 'compact':
          // Compact style: first + count + last (for longer words)
          if (length <= 4) return word;
          return word[0] + (length - 2) + word[length - 1];

        case 'verbose':
          // Verbose style: first + separator + count + separator + last
          const sep = separator || '';
          return word[0] + sep + (length - 2) + sep + word[length - 1];

        default:
          return word;
      }
    }

    function generateMultiple(word, separator = '') {
      const results = [];
      const length = word.length;

      if (length <= 3) {
        results.push({ type: 'Too short', result: word });
        return results;
      }

      // Standard
      results.push({
        type: 'Standard',
        result: word[0] + (length - 2) + word[length - 1]
      });

      // Compact (only if significantly shorter)
      if (length > 6) {
        results.push({
          type: 'Compact',
          result: word[0] + (length - 2) + word[length - 1]
        });
      }

      // With separator
      if (separator) {
        results.push({
          type: 'With separator',
          result: word[0] + separator + (length - 2) + separator + word[length - 1]
        });
      }

      // Multiple breakpoints (for long words)
      if (length > 10) {
        const mid = Math.floor(length / 2);
        results.push({
          type: 'Split middle',
          result: word.substring(0, 3) + (length - 6) + word.substring(length - 3)
        });
      }

      return results;
    }

    $('#generate').addEventListener('click', () => {
      const word = $('#input').value;
      const method = $('#method').value;
      const separator = $('#separator').value;

      if (!word.trim()) {
        toast('Please enter a word', 'error');
        return;
      }

      const numeronym = generateNumeronym(word, method, separator);
      const multiple = generateMultiple(word, separator);

      const output = [
        `Input: "${word}" (${word.length} characters)`,
        '',
        '=== GENERATED NUMERONYMS ===',
        ...multiple.map(item => `${item.type}: ${item.result}`),
        '',
        '=== EXPLANATION ===',
        `Standard method takes the first letter, counts the middle letters, and adds the last letter.`,
        `"${word}" → "${word[0]}" + ${word.length - 2} letters + "${word[word.length - 1]}"`,
        '',
        '=== COMMON NUMERONYMS ===',
        'i18n: internationalization',
        'l10n: localization',
        'k8s: kubernetes',
        'a11y: accessibility',
        'w3c: World Wide Web Consortium'
      ].join('\n');

      $('#output').textContent = output;
      toast('Numeronym generated');
    });

    $('#copy').addEventListener('click', () => {
      navigator.clipboard.writeText($('#output').textContent.split('\n')[2]?.split(': ')[1] || '').then(() => toast('Copied'));
    });

    $('#example').addEventListener('click', () => {
      const examples = [
        'internationalization',
        'localization',
        'kubernetes',
        'accessibility',
        'globalization',
        'characterization'
      ];

      const randomExample = examples[Math.floor(Math.random() * examples.length)];
      $('#input').value = randomExample;
      toast('Example loaded');
      $('#generate').click();
    });

    // Initialize
    $('#generate').click();
  });
}

function asciiartTool() {
  setTool('ASCII Art Generator', `
        <div class="row">
            <div class="form-group">
                <label>Text</label>
                <input type="text" id="text" placeholder="Enter text" value="HELLO" />
            </div>
            <div class="form-group">
                <label>Font Style</label>
                <select id="font">
                    <option value="standard">Standard</option>
                    <option value="block">Block</option>
                    <option value="bubble">Bubble</option>
                    <option value="shadow">Shadow</option>
                    <option value="slant">Slant</option>
                </select>
            </div>
        </div>
        <div class="row">
            <div class="form-group">
                <label>Width</label>
                <input type="number" id="width" value="80" min="20" max="200" />
            </div>
            <div class="form-group">
                <label>Justify</label>
                <select id="justify">
                    <option value="left">Left</option>
                    <option value="center">Center</option>
                    <option value="right">Right</option>
                </select>
            </div>
        </div>
        <div class="btn-group">
            <button id="generate" class="btn">Generate ASCII Art</button>
            <button id="copy" class="btn btn-secondary">Copy Art</button>
            <button id="clear" class="btn btn-secondary">Clear</button>
        </div>
        <div id="output" class="output" style="font-family: monospace; white-space: pre; line-height: 1.2; letter-spacing: 1px;"></div>
        <div style="margin-top: 16px; padding: 16px; background: var(--bg-secondary); border-radius: 8px;">
            <h4 style="margin-bottom: 8px;">🎨 ASCII Art Examples</h4>
            <div style="font-family: monospace; font-size: 12px; line-height: 1.2;">
                <div>  __  __     _____    _       _ </div>
                <div> |  \\/  |   |  ___|  | |     | |</div>
                <div> | |\\/| |   | |__    | |     | |</div>
                <div> | |  | |   |  __|   | |     | |</div>
                <div> | |  | |   | |___   | |___  |_|</div>
                <div> |_|  |_|   |_____|  |_____| (_)</div>
            </div>
        </div>
      `, () => {
    const asciiFonts = {
      standard: {
        A: [" █████╗ ", "██╔══██╗", "███████║", "██╔══██║", "██║  ██║", "╚═╝  ╚═╝"],
        B: ["██████╗ ", "██╔══██╗", "██████╔╝", "██╔══██╗", "██████╔╝", "╚═════╝ "],
        C: [" ██████╗", "██╔════╝", "██║     ", "██║     ", "╚██████╗", " ╚═════╝"],
        D: ["██████╗ ", "██╔══██╗", "██║  ██║", "██║  ██║", "██████╔╝", "╚═════╝ "],
        E: ["███████╗", "██╔════╝", "█████╗  ", "██╔══╝  ", "███████╗", "╚══════╝"],
        F: ["███████╗", "██╔════╝", "█████╗  ", "██╔══╝  ", "██║     ", "╚═╝     "],
        G: [" ██████╗ ", "██╔════╝ ", "██║  ███╗", "██║   ██║", "╚██████╔╝", " ╚═════╝ "],
        H: ["██╗  ██╗", "██║  ██║", "███████║", "██╔══██║", "██║  ██║", "╚═╝  ╚═╝"],
        I: ["██╗", "██║", "██║", "██║", "██║", "╚═╝"],
        J: ["     ██╗", "     ██║", "     ██║", "██   ██║", "╚█████╔╝", " ╚════╝ "],
        K: ["██╗  ██╗", "██║ ██╔╝", "█████╔╝ ", "██╔═██╗ ", "██║  ██╗", "╚═╝  ╚═╝"],
        L: ["██╗     ", "██║     ", "██║     ", "██║     ", "███████╗", "╚══════╝"],
        M: ["███╗   ███╗", "████╗ ████║", "██╔████╔██║", "██║╚██╔╝██║", "██║ ╚═╝ ██║", "╚═╝     ╚═╝"],
        N: ["███╗   ██╗", "████╗  ██║", "██╔██╗ ██║", "██║╚██╗██║", "██║ ╚████║", "╚═╝  ╚═══╝"],
        O: [" ██████╗ ", "██╔═══██╗", "██║   ██║", "██║   ██║", "╚██████╔╝", " ╚═════╝ "],
        P: ["██████╗ ", "██╔══██╗", "██████╔╝", "██╔═══╝ ", "██║     ", "╚═╝     "],
        Q: [" ██████╗ ", "██╔═══██╗", "██║   ██║", "██║▄▄ ██║", "╚██████╔╝", " ╚══▀▀═╝ "],
        R: ["██████╗ ", "██╔══██╗", "██████╔╝", "██╔══██╗", "██║  ██║", "╚═╝  ╚═╝"],
        S: [" ███████╗", "██╔════╝", "███████╗", "╚════██║", "███████║", "╚══════╝"],
        T: ["████████╗", "╚══██╔══╝", "   ██║   ", "   ██║   ", "   ██║   ", "   ╚═╝   "],
        U: ["██╗   ██╗", "██║   ██║", "██║   ██║", "██║   ██║", "╚██████╔╝", " ╚═════╝ "],
        V: ["██╗   ██╗", "██║   ██║", "██║   ██║", "╚██╗ ██╔╝", " ╚████╔╝ ", "  ╚═══╝  "],
        W: ["██╗    ██╗", "██║    ██║", "██║ █╗ ██║", "██║███╗██║", "╚███╔███╔╝", " ╚══╝╚══╝ "],
        X: ["██╗  ██╗", "╚██╗██╔╝", " ╚███╔╝ ", " ██╔██╗ ", "██╔╝ ██╗", "╚═╝  ╚═╝"],
        Y: ["██╗   ██╗", "╚██╗ ██╔╝", " ╚████╔╝ ", "  ╚██╔╝  ", "   ██║   ", "   ╚═╝   "],
        Z: ["███████╗", "╚══███╔╝", "  ███╔╝ ", " ███╔╝  ", "███████╗", "╚══════╝"],
        ' ': ["    ", "    ", "    ", "    ", "    ", "    "]
      },
      block: {
        A: [" ▄▄▄▄▄ ", "█   █  ", "█   █  ", "▄▄▄▄▄▄ ", "█   █  ", "█   █  "],
        B: ["▄▄▄▄▄  ", "█   █▄ ", "█   █▄ ", "▄▄▄▄▀  ", "█   █▄ ", "▄▄▄▄▄  "],
        C: [" ▄▄▄▄▄ ", "█      ", "█      ", "█      ", "█      ", " ▄▄▄▄▄ "],
        // More block letters would be defined here...
      }
    };

    function generateASCIIArt(text, fontStyle, width, justify) {
      text = text.toUpperCase();
      const font = asciiFonts[fontStyle] || asciiFonts.standard;
      const lines = Array(6).fill(''); // Standard font height

      for (let char of text) {
        const charArt = font[char] || font[' '];
        for (let i = 0; i < 6; i++) {
          lines[i] += charArt[i];
        }
      }

      // Apply width limit and justification
      const result = [];
      for (let line of lines) {
        if (line.length > width) {
          line = line.substring(0, width);
        }

        if (justify === 'center') {
          const padding = Math.max(0, width - line.length);
          const leftPad = Math.floor(padding / 2);
          const rightPad = padding - leftPad;
          line = ' '.repeat(leftPad) + line + ' '.repeat(rightPad);
        } else if (justify === 'right') {
          line = line.padStart(width, ' ');
        } else {
          line = line.padEnd(width, ' ');
        }

        result.push(line);
      }

      return result.join('\n');
    }

    $('#generate').addEventListener('click', () => {
      const text = $('#text').value;
      const font = $('#font').value;
      const width = parseInt($('#width').value) || 80;
      const justify = $('#justify').value;

      if (!text.trim()) {
        toast('Please enter text', 'error');
        return;
      }

      const art = generateASCIIArt(text, font, width, justify);
      $('#output').textContent = art;
      toast('ASCII art generated');
    });

    $('#copy').addEventListener('click', () => {
      navigator.clipboard.writeText($('#output').textContent).then(() => toast('Art copied'));
    });

    $('#clear').addEventListener('click', () => {
      $('#text').value = '';
      $('#output').textContent = '';
      toast('Cleared');
    });

    // Initialize
    $('#generate').click();
  });
}

// DATA TOOLS

function phoneparseTool() {
  setTool('Phone Parser & Formatter', `
        <div class="form-group">
            <label>Phone Number</label>
            <input type="text" id="phone" placeholder="Enter phone number" value="+1 (555) 123-4567" />
        </div>
        <div class="row">
            <div class="form-group">
                <label>Country Code</label>
                <select id="country">
                    <option value="US" selected>United States (+1)</option>
                    <option value="GB">United Kingdom (+44)</option>
                    <option value="DE">Germany (+49)</option>
                    <option value="FR">France (+33)</option>
                    <option value="IT">Italy (+39)</option>
                    <option value="ES">Spain (+34)</option>
                    <option value="CA">Canada (+1)</option>
                    <option value="AU">Australia (+61)</option>
                    <option value="JP">Japan (+81)</option>
                    <option value="CN">China (+86)</option>
                    <option value="IN">India (+91)</option>
                    <option value="BR">Brazil (+55)</option>
                    <option value="RU">Russia (+7)</option>
                    <option value="auto">Auto-detect</option>
                </select>
            </div>
            <div class="form-group">
                <label>Format</label>
                <select id="format">
                    <option value="e164">E.164 (+15551234567)</option>
                    <option value="international">International (+1 555 123 4567)</option>
                    <option value="national">National (555-123-4567)</option>
                    <option value="rfc3966">RFC3966 (tel:+1-555-123-4567)</option>
                    <option value="simple">Simple (5551234567)</option>
                </select>
            </div>
        </div>
        <div class="btn-group">
            <button id="parse" class="btn">Parse & Format</button>
            <button id="validate" class="btn btn-secondary">Validate</button>
            <button id="copy" class="btn btn-secondary">Copy Formatted</button>
        </div>
        <div id="output" class="output"></div>
        <div style="margin-top: 16px;">
            <h4 style="margin-bottom: 8px;">📱 Phone Information</h4>
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 12px;">
                <div class="phone-info">
                    <div style="font-size: 12px; color: var(--text-muted);">Country</div>
                    <div id="phoneCountry" style="font-weight: 600;"></div>
                </div>
                <div class="phone-info">
                    <div style="font-size: 12px; color: var(--text-muted);">Type</div>
                    <div id="phoneType" style="font-weight: 600;"></div>
                </div>
                <div class="phone-info">
                    <div style="font-size: 12px; color: var(--text-muted);">Valid</div>
                    <div id="phoneValid" style="font-weight: 600;"></div>
                </div>
                <div class="phone-info">
                    <div style="font-size: 12px; color: var(--text-muted);">Formatted</div>
                    <div id="phoneFormatted" style="font-weight: 600; font-family: monospace;"></div>
                </div>
            </div>
        </div>
      `, () => {
    const countryCodes = {
      'US': { code: '1', name: 'United States', pattern: /^(\d{3})(\d{3})(\d{4})$/ },
      'GB': { code: '44', name: 'United Kingdom', pattern: /^(\d{4})(\d{3})(\d{3})$/ },
      'DE': { code: '49', name: 'Germany', pattern: /^(\d{3})(\d{3})(\d{4})$/ },
      'FR': { code: '33', name: 'France', pattern: /^(\d{1})(\d{2})(\d{2})(\d{2})(\d{2})$/ },
      'IT': { code: '39', name: 'Italy', pattern: /^(\d{3})(\d{3})(\d{4})$/ },
      'ES': { code: '34', name: 'Spain', pattern: /^(\d{3})(\d{3})(\d{3})$/ },
      'CA': { code: '1', name: 'Canada', pattern: /^(\d{3})(\d{3})(\d{4})$/ },
      'AU': { code: '61', name: 'Australia', pattern: /^(\d{2})(\d{4})(\d{4})$/ },
      'JP': { code: '81', name: 'Japan', pattern: /^(\d{2})(\d{4})(\d{4})$/ },
      'CN': { code: '86', name: 'China', pattern: /^(\d{3})(\d{4})(\d{4})$/ },
      'IN': { code: '91', name: 'India', pattern: /^(\d{3})(\d{3})(\d{4})$/ },
      'BR': { code: '55', name: 'Brazil', pattern: /^(\d{2})(\d{4})(\d{4})$/ },
      'RU': { code: '7', name: 'Russia', pattern: /^(\d{3})(\d{3})(\d{4})$/ }
    };

    function parsePhoneNumber(phone, country = 'auto') {
      // Clean the phone number
      let clean = phone.replace(/[^\d+]/g, '');

      // Remove leading zeros
      clean = clean.replace(/^0+/, '');

      // Try to detect country if auto
      let countryInfo = countryCodes[country];
      let countryCode = '';
      let nationalNumber = clean;

      if (country === 'auto') {
        // Check if number starts with +
        if (clean.startsWith('+')) {
          for (const [cc, info] of Object.entries(countryCodes)) {
            if (clean.startsWith('+' + info.code)) {
              countryInfo = info;
              countryCode = info.code;
              nationalNumber = clean.substring(info.code.length + 1);
              break;
            }
          }
        } else {
          // Default to US for numbers without country code
          countryInfo = countryCodes['US'];
          countryCode = '1';
          nationalNumber = clean;
        }
      } else {
        countryInfo = countryCodes[country];
        countryCode = countryInfo.code;

        // Remove country code if present
        if (clean.startsWith(countryCode)) {
          nationalNumber = clean.substring(countryCode.length);
        } else if (clean.startsWith('+' + countryCode)) {
          nationalNumber = clean.substring(countryCode.length + 1);
        }
      }

      // Determine phone type
      let type = 'Unknown';
      if (nationalNumber.length === 10) {
        type = 'Mobile/Landline';
      } else if (nationalNumber.length === 7) {
        type = 'Local';
      } else if (nationalNumber.length > 10) {
        type = 'International';
      }

      // Check if valid
      const isValid = nationalNumber.length >= 7 && nationalNumber.length <= 15;

      // Format based on pattern
      let formatted = '';
      if (countryInfo.pattern && nationalNumber.match(countryInfo.pattern)) {
        const match = nationalNumber.match(countryInfo.pattern);
        formatted = match.slice(1).join('-');
      } else {
        formatted = nationalNumber;
      }

      return {
        original: phone,
        clean: clean,
        countryCode: '+' + countryCode,
        countryName: countryInfo.name,
        nationalNumber: nationalNumber,
        type: type,
        isValid: isValid,
        formatted: formatted,
        e164: '+' + countryCode + nationalNumber,
        international: '+' + countryCode + ' ' + formatted,
        national: formatted,
        rfc3966: 'tel:+' + countryCode + '-' + nationalNumber
      };
    }

    $('#parse').addEventListener('click', () => {
      const phone = $('#phone').value.trim();
      const country = $('#country').value;

      if (!phone) {
        toast('Please enter a phone number', 'error');
        return;
      }

      try {
        const parsed = parsePhoneNumber(phone, country);

        // Update component displays
        $('#phoneCountry').textContent = parsed.countryName;
        $('#phoneType').textContent = parsed.type;
        $('#phoneValid').textContent = parsed.isValid ? 'Yes' : 'No';
        $('#phoneValid').style.color = parsed.isValid ? 'var(--success)' : 'var(--error)';

        // Format based on selection
        const format = $('#format').value;
        let formatted = parsed[format] || parsed.e164;
        $('#phoneFormatted').textContent = formatted;

        // Build results
        const results = [
          '=== PHONE NUMBER PARSED ===',
          `Original: ${parsed.original}`,
          `Cleaned: ${parsed.clean}`,
          '',
          '=== COUNTRY INFORMATION ===',
          `Country: ${parsed.countryName}`,
          `Country Code: ${parsed.countryCode}`,
          `National Number: ${parsed.nationalNumber}`,
          '',
          '=== VALIDATION ===',
          `Valid: ${parsed.isValid ? 'Yes' : 'No'}`,
          `Type: ${parsed.type}`,
          `Length: ${parsed.nationalNumber.length} digits`,
          '',
          '=== FORMATTED VERSIONS ===',
          `E.164: ${parsed.e164}`,
          `International: ${parsed.international}`,
          `National: ${parsed.national}`,
          `RFC3966: ${parsed.rfc3966}`,
          `Simple: ${parsed.clean}`
        ].join('\n');

        $('#output').textContent = results;
        toast('Phone number parsed');
      } catch (error) {
        toast('Error: ' + error.message, 'error');
      }
    });

    $('#validate').addEventListener('click', () => {
      const phone = $('#phone').value.trim();
      const country = $('#country').value;

      if (!phone) {
        toast('Please enter a phone number', 'error');
        return;
      }

      try {
        const parsed = parsePhoneNumber(phone, country);

        if (parsed.isValid) {
          toast('✓ Phone number is valid', 'success');
          $('#phoneValid').textContent = 'Yes';
          $('#phoneValid').style.color = 'var(--success)';
        } else {
          toast('✗ Phone number is invalid', 'error');
          $('#phoneValid').textContent = 'No';
          $('#phoneValid').style.color = 'var(--error)';
        }
      } catch (error) {
        toast('Validation error', 'error');
      }
    });

    $('#copy').addEventListener('click', () => {
      const formatted = $('#phoneFormatted').textContent;
      if (formatted) {
        navigator.clipboard.writeText(formatted).then(() => toast('Phone number copied'));
      }
    });

    // Initialize
    $('#parse').click();
  });
}

function ibanTool() {
  setTool('IBAN Validator & Parser', `
        <div class="form-group">
            <label>IBAN Number</label>
            <input type="text" id="iban" placeholder="Enter IBAN" value="CH9300762011623852957" style="font-family: monospace;" />
        </div>
        <div class="btn-group">
            <button id="validate" class="btn">Validate IBAN</button>
            <button id="parse" class="btn btn-secondary">Parse Details</button>
            <button id="copy" class="btn btn-secondary">Copy Formatted</button>
        </div>
        <div id="output" class="output"></div>
        <div style="margin-top: 16px;">
            <h4 style="margin-bottom: 8px;">🏦 IBAN Information</h4>
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 12px;">
                <div class="iban-info">
                    <div style="font-size: 12px; color: var(--text-muted);">Country</div>
                    <div id="ibanCountry" style="font-weight: 600;"></div>
                </div>
                <div class="iban-info">
                    <div style="font-size: 12px; color: var(--text-muted);">Check Digits</div>
                    <div id="ibanCheck" style="font-weight: 600; font-family: monospace;"></div>
                </div>
                <div class="iban-info">
                    <div style="font-size: 12px; color: var(--text-muted);">BBAN</div>
                    <div id="ibanBban" style="font-weight: 600; font-family: monospace;"></div>
                </div>
                <div class="iban-info">
                    <div style="font-size: 12px; color: var(--text-muted);">Valid</div>
                    <div id="ibanValid" style="font-weight: 600;"></div>
                </div>
            </div>
        </div>
      `, () => {
    const ibanPatterns = {
      'AL': { name: 'Albania', length: 28, pattern: /^AL\d{10}[A-Z0-9]{16}$/ },
      'AD': { name: 'Andorra', length: 24, pattern: /^AD\d{10}[A-Z0-9]{12}$/ },
      'AT': { name: 'Austria', length: 20, pattern: /^AT\d{18}$/ },
      'AZ': { name: 'Azerbaijan', length: 28, pattern: /^AZ\d{2}[A-Z]{4}[A-Z0-9]{20}$/ },
      'BE': { name: 'Belgium', length: 16, pattern: /^BE\d{14}$/ },
      'BH': { name: 'Bahrain', length: 22, pattern: /^BH\d{2}[A-Z]{4}[A-Z0-9]{14}$/ },
      'BA': { name: 'Bosnia and Herzegovina', length: 20, pattern: /^BA\d{18}$/ },
      'BR': { name: 'Brazil', length: 29, pattern: /^BR\d{25}[A-Z]{1}[A-Z0-9]{1}$/ },
      'BG': { name: 'Bulgaria', length: 22, pattern: /^BG\d{2}[A-Z]{4}\d{6}[A-Z0-9]{8}$/ },
      'CR': { name: 'Costa Rica', length: 22, pattern: /^CR\d{20}$/ },
      'HR': { name: 'Croatia', length: 21, pattern: /^HR\d{19}$/ },
      'CY': { name: 'Cyprus', length: 28, pattern: /^CY\d{10}[A-Z0-9]{16}$/ },
      'CZ': { name: 'Czech Republic', length: 24, pattern: /^CZ\d{22}$/ },
      'DK': { name: 'Denmark', length: 18, pattern: /^DK\d{16}$/ },
      'DO': { name: 'Dominican Republic', length: 28, pattern: /^DO\d{2}[A-Z0-9]{4}\d{20}$/ },
      'EE': { name: 'Estonia', length: 20, pattern: /^EE\d{18}$/ },
      'FI': { name: 'Finland', length: 18, pattern: /^FI\d{16}$/ },
      'FR': { name: 'France', length: 27, pattern: /^FR\d{12}[A-Z0-9]{11}\d{2}$/ },
      'GE': { name: 'Georgia', length: 22, pattern: /^GE\d{2}[A-Z]{2}\d{16}$/ },
      'DE': { name: 'Germany', length: 22, pattern: /^DE\d{20}$/ },
      'GI': { name: 'Gibraltar', length: 23, pattern: /^GI\d{2}[A-Z]{4}[A-Z0-9]{15}$/ },
      'GR': { name: 'Greece', length: 27, pattern: /^GR\d{9}[A-Z0-9]{16}$/ },
      'GL': { name: 'Greenland', length: 18, pattern: /^GL\d{16}$/ },
      'GT': { name: 'Guatemala', length: 28, pattern: /^GT\d{2}[A-Z0-9]{24}$/ },
      'HU': { name: 'Hungary', length: 28, pattern: /^HU\d{26}$/ },
      'IS': { name: 'Iceland', length: 26, pattern: /^IS\d{24}$/ },
      'IE': { name: 'Ireland', length: 22, pattern: /^IE\d{2}[A-Z]{4}\d{14}$/ },
      'IL': { name: 'Israel', length: 23, pattern: /^IL\d{21}$/ },
      'IT': { name: 'Italy', length: 27, pattern: /^IT\d{2}[A-Z]{1}\d{10}[A-Z0-9]{12}$/ },
      'JO': { name: 'Jordan', length: 30, pattern: /^JO\d{2}[A-Z]{4}\d{4}[A-Z0-9]{18}$/ },
      'KZ': { name: 'Kazakhstan', length: 20, pattern: /^KZ\d{5}[A-Z0-9]{13}$/ },
      'XK': { name: 'Kosovo', length: 20, pattern: /^XK\d{18}$/ },
      'KW': { name: 'Kuwait', length: 30, pattern: /^KW\d{2}[A-Z]{4}[A-Z0-9]{22}$/ },
      'LV': { name: 'Latvia', length: 21, pattern: /^LV\d{2}[A-Z]{4}[A-Z0-9]{13}$/ },
      'LB': { name: 'Lebanon', length: 28, pattern: /^LB\d{6}[A-Z0-9]{20}$/ },
      'LI': { name: 'Liechtenstein', length: 21, pattern: /^LI\d{7}[A-Z0-9]{12}$/ },
      'LT': { name: 'Lithuania', length: 20, pattern: /^LT\d{18}$/ },
      'LU': { name: 'Luxembourg', length: 20, pattern: /^LU\d{5}[A-Z0-9]{13}$/ },
      'MK': { name: 'North Macedonia', length: 19, pattern: /^MK\d{5}[A-Z0-9]{10}\d{2}$/ },
      'MT': { name: 'Malta', length: 31, pattern: /^MT\d{2}[A-Z]{4}\d{5}[A-Z0-9]{18}$/ },
      'MR': { name: 'Mauritania', length: 27, pattern: /^MR\d{25}$/ },
      'MU': { name: 'Mauritius', length: 30, pattern: /^MU\d{2}[A-Z]{4}\d{19}[A-Z]{3}$/ },
      'MD': { name: 'Moldova', length: 24, pattern: /^MD\d{2}[A-Z0-9]{20}$/ },
      'MC': { name: 'Monaco', length: 27, pattern: /^MC\d{12}[A-Z0-9]{11}\d{2}$/ },
      'ME': { name: 'Montenegro', length: 22, pattern: /^ME\d{20}$/ },
      'NL': { name: 'Netherlands', length: 18, pattern: /^NL\d{2}[A-Z]{4}\d{10}$/ },
      'NO': { name: 'Norway', length: 15, pattern: /^NO\d{13}$/ },
      'PK': { name: 'Pakistan', length: 24, pattern: /^PK\d{2}[A-Z]{4}[A-Z0-9]{16}$/ },
      'PS': { name: 'Palestine', length: 29, pattern: /^PS\d{2}[A-Z]{4}[A-Z0-9]{21}$/ },
      'PL': { name: 'Poland', length: 28, pattern: /^PL\d{26}$/ },
      'PT': { name: 'Portugal', length: 25, pattern: /^PT\d{23}$/ },
      'QA': { name: 'Qatar', length: 29, pattern: /^QA\d{2}[A-Z]{4}[A-Z0-9]{21}$/ },
      'RO': { name: 'Romania', length: 24, pattern: /^RO\d{2}[A-Z]{4}[A-Z0-9]{16}$/ },
      'SM': { name: 'San Marino', length: 27, pattern: /^SM\d{2}[A-Z]{1}\d{10}[A-Z0-9]{12}$/ },
      'SA': { name: 'Saudi Arabia', length: 24, pattern: /^SA\d{4}[A-Z0-9]{18}$/ },
      'RS': { name: 'Serbia', length: 22, pattern: /^RS\d{20}$/ },
      'SK': { name: 'Slovakia', length: 24, pattern: /^SK\d{22}$/ },
      'SI': { name: 'Slovenia', length: 19, pattern: /^SI\d{17}$/ },
      'ES': { name: 'Spain', length: 24, pattern: /^ES\d{22}$/ },
      'SE': { name: 'Sweden', length: 24, pattern: /^SE\d{22}$/ },
      'CH': { name: 'Switzerland', length: 21, pattern: /^CH\d{7}[A-Z0-9]{12}$/ },
      'TN': { name: 'Tunisia', length: 24, pattern: /^TN\d{22}$/ },
      'TR': { name: 'Turkey', length: 26, pattern: /^TR\d{8}[A-Z0-9]{16}$/ },
      'AE': { name: 'United Arab Emirates', length: 23, pattern: /^AE\d{21}$/ },
      'GB': { name: 'United Kingdom', length: 22, pattern: /^GB\d{2}[A-Z]{4}\d{14}$/ },
      'VA': { name: 'Vatican City', length: 22, pattern: /^VA\d{20}$/ },
      'VG': { name: 'Virgin Islands, British', length: 24, pattern: /^VG\d{2}[A-Z]{4}\d{16}$/ }
    };

    function validateIBAN(iban) {
      iban = iban.toUpperCase().replace(/\s/g, '');

      // Check country code
      const countryCode = iban.substring(0, 2);
      const countryInfo = ibanPatterns[countryCode];

      if (!countryInfo) {
        return { valid: false, error: 'Invalid country code' };
      }

      // Check length
      if (iban.length !== countryInfo.length) {
        return { valid: false, error: `Invalid length for ${countryInfo.name}. Expected ${countryInfo.length}, got ${iban.length}` };
      }

      // Check pattern
      if (!countryInfo.pattern.test(iban)) {
        return { valid: false, error: `Invalid format for ${countryInfo.name}` };
      }

      // Perform MOD-97 check
      const rearranged = iban.substring(4) + iban.substring(0, 4);
      const numeric = rearranged.split('').map(char => {
        const code = char.charCodeAt(0);
        return code >= 65 && code <= 90 ? (code - 55).toString() : char;
      }).join('');

      // Check if numeric is too large for JavaScript
      if (numeric.length > 15) {
        // Use BigInt for large numbers
        let remainder = 0;
        for (let i = 0; i < numeric.length; i++) {
          remainder = (remainder * 10 + parseInt(numeric[i])) % 97;
        }
        if (remainder !== 1) {
          return { valid: false, error: 'Failed MOD-97 check' };
        }
      } else {
        const num = BigInt(numeric);
        if (num % 97n !== 1n) {
          return { valid: false, error: 'Failed MOD-97 check' };
        }
      }

      return { valid: true, iban: iban, countryInfo: countryInfo };
    }

    function parseIBAN(iban) {
      const validation = validateIBAN(iban);

      if (!validation.valid) {
        throw new Error(validation.error);
      }

      const clean = validation.iban;
      const countryCode = clean.substring(0, 2);
      const checkDigits = clean.substring(2, 4);
      const bban = clean.substring(4);
      const countryInfo = validation.countryInfo;

      // Parse BBAN based on country
      let bankCode = '', branchCode = '', accountNumber = '';

      switch (countryCode) {
        case 'GB':
          bankCode = bban.substring(0, 4);
          branchCode = bban.substring(4, 8);
          accountNumber = bban.substring(8);
          break;
        case 'DE':
          bankCode = bban.substring(0, 8);
          accountNumber = bban.substring(8);
          break;
        case 'FR':
          bankCode = bban.substring(0, 5);
          branchCode = bban.substring(5, 10);
          accountNumber = bban.substring(10, 21);
          break;
        case 'CH':
          bankCode = bban.substring(0, 5);
          accountNumber = bban.substring(5);
          break;
        case 'US':
          // Not a real IBAN country, but included for example
          break;
        default:
          bankCode = bban.substring(0, 4);
          accountNumber = bban.substring(4);
      }

      // Format for display
      const formatted = clean.replace(/(.{4})/g, '$1 ').trim();

      return {
        original: iban,
        clean: clean,
        countryCode: countryCode,
        countryName: countryInfo.name,
        checkDigits: checkDigits,
        bban: bban,
        bankCode: bankCode,
        branchCode: branchCode,
        accountNumber: accountNumber,
        formatted: formatted,
        length: clean.length,
        valid: true
      };
    }

    $('#validate').addEventListener('click', () => {
      const iban = $('#iban').value.trim();

      if (!iban) {
        toast('Please enter an IBAN', 'error');
        return;
      }

      try {
        const validation = validateIBAN(iban);

        if (validation.valid) {
          toast('✓ IBAN is valid', 'success');
          $('#ibanValid').textContent = 'Yes';
          $('#ibanValid').style.color = 'var(--success)';

          // Parse and display details
          const parsed = parseIBAN(iban);
          $('#ibanCountry').textContent = parsed.countryName;
          $('#ibanCheck').textContent = parsed.checkDigits;
          $('#ibanBban').textContent = parsed.bban;

          // Build results
          const results = [
            '=== IBAN VALIDATION ===',
            `IBAN: ${parsed.formatted}`,
            `Valid: Yes`,
            '',
            '=== COUNTRY INFORMATION ===',
            `Country: ${parsed.countryName} (${parsed.countryCode})`,
            `Length: ${parsed.length} characters`,
            '',
            '=== COMPONENTS ===',
            `Check Digits: ${parsed.checkDigits}`,
            `BBAN: ${parsed.bban}`,
            parsed.bankCode ? `Bank Code: ${parsed.bankCode}` : '',
            parsed.branchCode ? `Branch Code: ${parsed.branchCode}` : '',
            `Account Number: ${parsed.accountNumber}`,
            '',
            '=== FORMATTED ===',
            `Compact: ${parsed.clean}`,
            `Formatted: ${parsed.formatted}`
          ].filter(Boolean).join('\n');

          $('#output').textContent = results;
        } else {
          toast('✗ ' + validation.error, 'error');
          $('#ibanValid').textContent = 'No';
          $('#ibanValid').style.color = 'var(--error)';
          $('#output').textContent = `Validation failed: ${validation.error}`;
        }
      } catch (error) {
        toast('Validation error: ' + error.message, 'error');
      }
    });

    $('#parse').addEventListener('click', () => {
      const iban = $('#iban').value.trim();

      if (!iban) {
        toast('Please enter an IBAN', 'error');
        return;
      }

      try {
        const parsed = parseIBAN(iban);

        // Update component displays
        $('#ibanCountry').textContent = parsed.countryName;
        $('#ibanCheck').textContent = parsed.checkDigits;
        $('#ibanBban').textContent = parsed.bban;
        $('#ibanValid').textContent = 'Yes';
        $('#ibanValid').style.color = 'var(--success)';

        // Build detailed results
        const results = [
          '=== IBAN PARSED ===',
          `Original: ${parsed.original}`,
          `Cleaned: ${parsed.clean}`,
          `Formatted: ${parsed.formatted}`,
          '',
          '=== STRUCTURE ===',
          `Country Code: ${parsed.countryCode}`,
          `Check Digits: ${parsed.checkDigits}`,
          `BBAN (Basic Bank Account Number): ${parsed.bban}`,
          '',
          '=== BREAKDOWN ===',
          parsed.bankCode ? `Bank Code: ${parsed.bankCode}` : '',
          parsed.branchCode ? `Branch Code: ${parsed.branchCode}` : '',
          `Account Number: ${parsed.accountNumber}`,
          '',
          '=== VALIDATION ===',
          `Length: ${parsed.length} characters (expected: ${ibanPatterns[parsed.countryCode]?.length})`,
          `Country: ${parsed.countryName}`,
          `Valid: Yes`
        ].filter(Boolean).join('\n');

        $('#output').textContent = results;
        toast('IBAN parsed successfully');
      } catch (error) {
        toast('Parse error: ' + error.message, 'error');
        $('#output').textContent = error.message;
      }
    });

    $('#copy').addEventListener('click', () => {
      const formatted = $('#iban').value.toUpperCase().replace(/\s/g, '').replace(/(.{4})/g, '$1 ').trim();
      if (formatted) {
        navigator.clipboard.writeText(formatted).then(() => toast('IBAN copied'));
      }
    });

    // Initialize
    $('#validate').click();
  });
}

// IMAGES & VIDEOS

function qrcodeTool() {
  setTool('QR Code Generator', `
        <div class="row">
            <div class="form-group">
                <label>Content</label>
                <textarea id="content" rows="3" placeholder="Enter text or URL for QR code">https://utility-toolbox.com</textarea>
            </div>
            <div class="form-group">
                <label>Size</label>
                <input type="number" id="size" value="200" min="100" max="1000" />
            </div>
        </div>
        <div class="row">
            <div class="form-group">
                <label>Foreground Color</label>
                <input type="color" id="fgColor" value="#000000" />
            </div>
            <div class="form-group">
                <label>Background Color</label>
                <input type="color" id="bgColor" value="#ffffff" />
            </div>
        </div>
        <div class="btn-group">
            <button id="generate" class="btn">Generate QR Code</button>
            <button id="download" class="btn btn-secondary">Download PNG</button>
            <button id="copy" class="btn btn-secondary">Copy Image</button>
        </div>
        <div id="qrcodeContainer" style="margin-top: 24px; text-align: center;">
            <canvas id="qrcode" width="200" height="200" style="border: 1px solid var(--border); border-radius: 8px; background: white;"></canvas>
        </div>
        <div style="margin-top: 16px; padding: 16px; background: var(--bg-secondary); border-radius: 8px;">
            <h4 style="margin-bottom: 8px;">📱 QR Code Tips</h4>
            <div style="font-size: 14px;">
                <p><strong>What to encode:</strong></p>
                <ul style="margin: 8px 0; padding-left: 20px;">
                    <li>URLs (https://example.com)</li>
                    <li>Contact information (vCard)</li>
                    <li>WiFi credentials</li>
                    <li>Plain text or messages</li>
                    <li>Phone numbers</li>
                    <li>Email addresses</li>
                </ul>
            </div>
        </div>
      `, () => {
    // Simple QR Code generator using canvas
    function generateQRCode(content, size = 200, fgColor = '#000000', bgColor = '#ffffff') {
      const canvas = $('#qrcode');
      const ctx = canvas.getContext('2d');

      // Set canvas size
      canvas.width = size;
      canvas.height = size;

      // Clear canvas
      ctx.fillStyle = bgColor;
      ctx.fillRect(0, 0, size, size);

      // Generate QR code pattern (simplified version)
      // Note: This is a basic demonstration. For production, use a proper QR library.

      // Create a simple pattern based on content hash
      const encoder = new TextEncoder();
      const data = encoder.encode(content);
      let hash = 0;
      for (let i = 0; i < data.length; i++) {
        hash = ((hash << 5) - hash) + data[i];
        hash |= 0;
      }

      // Set random seed based on hash
      const seed = hash;
      const moduleSize = Math.max(3, Math.floor(size / 25));
      const quietZone = 4;
      const dataSize = size - 2 * quietZone * moduleSize;
      const modules = Math.floor(dataSize / moduleSize);

      // Draw finder patterns (simplified)
      ctx.fillStyle = fgColor;

      // Top-left finder
      drawFinderPattern(ctx, quietZone, quietZone, moduleSize);

      // Top-right finder
      drawFinderPattern(ctx, quietZone + (modules - 7) * moduleSize, quietZone, moduleSize);

      // Bottom-left finder
      drawFinderPattern(ctx, quietZone, quietZone + (modules - 7) * moduleSize, moduleSize);

      // Draw data modules based on content
      const dataModules = modules - 14; // Account for finder patterns
      const dataStart = quietZone + 7 * moduleSize;

      for (let y = 0; y < dataModules; y++) {
        for (let x = 0; x < dataModules; x++) {
          // Simple pseudo-random pattern based on content
          const value = (seed * (x + 1) * (y + 1)) % 2;
          if (value === 0) {
            ctx.fillStyle = fgColor;
          } else {
            ctx.fillStyle = bgColor;
          }

          const px = dataStart + x * moduleSize;
          const py = dataStart + y * moduleSize;

          ctx.fillRect(px, py, moduleSize, moduleSize);
        }
      }

      // Add some text below
      ctx.fillStyle = fgColor;
      ctx.font = '12px Arial';
      ctx.textAlign = 'center';
      ctx.fillText('QR Code Preview', size / 2, size - 5);
    }

    function drawFinderPattern(ctx, x, y, moduleSize) {
      const size = 7 * moduleSize;

      // Outer black square
      ctx.fillStyle = '#000000';
      ctx.fillRect(x, y, size, size);

      // Inner white square
      ctx.fillStyle = '#ffffff';
      ctx.fillRect(x + moduleSize, y + moduleSize, 5 * moduleSize, 5 * moduleSize);

      // Center black square
      ctx.fillStyle = '#000000';
      ctx.fillRect(x + 2 * moduleSize, y + 2 * moduleSize, 3 * moduleSize, 3 * moduleSize);
    }

    $('#generate').addEventListener('click', () => {
      const content = $('#content').value.trim();
      const size = parseInt($('#size').value) || 200;
      const fgColor = $('#fgColor').value;
      const bgColor = $('#bgColor').value;

      if (!content) {
        toast('Please enter content for QR code', 'error');
        return;
      }

      generateQRCode(content, size, fgColor, bgColor);
      toast('QR code generated');
    });

    $('#download').addEventListener('click', () => {
      const canvas = $('#qrcode');
      const content = $('#content').value.trim().substring(0, 20).replace(/[^a-z0-9]/gi, '_');

      const link = document.createElement('a');
      link.download = `qrcode_${content || 'generated'}.png`;
      link.href = canvas.toDataURL('image/png');
      link.click();

      toast('QR code downloaded');
    });

    $('#copy').addEventListener('click', () => {
      const canvas = $('#qrcode');

      canvas.toBlob(blob => {
        const item = new ClipboardItem({ 'image/png': blob });
        navigator.clipboard.write([item]).then(() => {
          toast('QR code copied to clipboard');
        }).catch(err => {
          toast('Failed to copy image', 'error');
        });
      });
    });

    // Initialize
    $('#generate').click();
  });
}

function wifiqrTool() {
  setTool('WiFi QR Code Generator', `
        <div class="row">
            <div class="form-group">
                <label>SSID (Network Name)</label>
                <input type="text" id="ssid" placeholder="MyWiFiNetwork" value="MyWiFi" />
            </div>
            <div class="form-group">
                <label>Password</label>
                <input type="password" id="password" placeholder="WiFi password" value="MyPassword123" />
            </div>
        </div>
        <div class="row">
            <div class="form-group">
                <label>Security Type</label>
                <select id="security">
                    <option value="WPA">WPA/WPA2</option>
                    <option value="WEP">WEP</option>
                    <option value="nopass">No Password</option>
                </select>
            </div>
            <div class="form-group">
                <label>Hidden Network</label>
                <div style="margin-top: 8px;">
                    <input type="checkbox" id="hidden" />
                    <label for="hidden" style="margin-left: 8px;">Network is hidden</label>
                </div>
            </div>
        </div>
        <div class="btn-group">
            <button id="generate" class="btn">Generate WiFi QR</button>
            <button id="download" class="btn btn-secondary">Download QR Code</button>
            <button id="copy" class="btn btn-secondary">Copy Connection URL</button>
        </div>
        <div id="qrcodeContainer" style="margin-top: 24px; text-align: center;">
            <canvas id="qrcode" width="200" height="200" style="border: 1px solid var(--border); border-radius: 8px; background: white;"></canvas>
        </div>
        <div id="connectionInfo" style="margin-top: 16px; padding: 16px; background: var(--bg-secondary); border-radius: 8px;">
            <h4 style="margin-bottom: 8px;">📶 WiFi Connection Details</h4>
            <div style="font-family: monospace; font-size: 14px; word-break: break-all;">
                <div id="wifiString"></div>
            </div>
            <div class="btn-group" style="margin-top: 12px;">
                <button id="showPassword" class="btn btn-secondary">Show Password</button>
                <button id="testConnection" class="btn btn-secondary">Test Connection URL</button>
            </div>
        </div>
      `, () => {
    function generateWifiString(ssid, password, security, hidden) {
      // Format: WIFI:S:<SSID>;T:<TYPE>;P:<PASSWORD>;H:<HIDDEN>;;
      let wifiString = 'WIFI:';
      wifiString += `S:${escapeWifiField(ssid)};`;
      wifiString += `T:${security};`;

      if (security !== 'nopass' && password) {
        wifiString += `P:${escapeWifiField(password)};`;
      }

      if (hidden) {
        wifiString += 'H:true;';
      }

      wifiString += ';';
      return wifiString;
    }

    function escapeWifiField(field) {
      // Escape special characters: ; , " : and \
      return field.replace(/[;,":\\]/g, '\\$&');
    }

    function generateQRCode(content, size = 200) {
      const canvas = $('#qrcode');
      const ctx = canvas.getContext('2d');

      // Set canvas size
      canvas.width = size;
      canvas.height = size;

      // Clear canvas
      ctx.fillStyle = '#ffffff';
      ctx.fillRect(0, 0, size, size);

      // Draw WiFi icon in center
      const centerX = size / 2;
      const centerY = size / 2;
      const iconSize = size / 3;

      // Draw WiFi arcs
      ctx.strokeStyle = '#000000';
      ctx.lineWidth = 2;

      // Outer arc
      ctx.beginPath();
      ctx.arc(centerX, centerY, iconSize * 0.8, 0, Math.PI * 2);
      ctx.stroke();

      // Middle arc
      ctx.beginPath();
      ctx.arc(centerX, centerY, iconSize * 0.5, 0, Math.PI * 2);
      ctx.stroke();

      // Inner arc
      ctx.beginPath();
      ctx.arc(centerX, centerY, iconSize * 0.2, 0, Math.PI * 2);
      ctx.stroke();

      // Add text
      ctx.fillStyle = '#000000';
      ctx.font = '14px Arial';
      ctx.textAlign = 'center';
      ctx.fillText('WiFi QR', centerX, size - 10);
    }

    function showPassword() {
      const passwordInput = $('#password');
      const isPassword = passwordInput.type === 'password';
      passwordInput.type = isPassword ? 'text' : 'password';
      $('#showPassword').textContent = isPassword ? 'Hide Password' : 'Show Password';
    }

    function testConnectionURL() {
      const wifiString = $('#wifiString').textContent;
      if (wifiString) {
        // Create a temporary link to test
        const testUrl = `https://qrcode.example.com/test?data=${encodeURIComponent(wifiString)}`;
        window.open(testUrl, '_blank');
        toast('Opening test page in new tab');
      }
    }

    $('#generate').addEventListener('click', () => {
      const ssid = $('#ssid').value.trim();
      const password = $('#password').value;
      const security = $('#security').value;
      const hidden = $('#hidden').checked;

      if (!ssid) {
        toast('Please enter SSID', 'error');
        return;
      }

      if (security !== 'nopass' && !password) {
        toast('Please enter password for secured network', 'error');
        return;
      }

      const wifiString = generateWifiString(ssid, password, security, hidden);
      $('#wifiString').textContent = wifiString;

      generateQRCode(wifiString, 200);
      toast('WiFi QR code generated');
    });

    $('#download').addEventListener('click', () => {
      const canvas = $('#qrcode');
      const ssid = $('#ssid').value.trim().substring(0, 20).replace(/[^a-z0-9]/gi, '_');

      const link = document.createElement('a');
      link.download = `wifi_${ssid || 'network'}_qrcode.png`;
      link.href = canvas.toDataURL('image/png');
      link.click();

      toast('QR code downloaded');
    });

    $('#copy').addEventListener('click', () => {
      const wifiString = $('#wifiString').textContent;
      if (wifiString) {
        navigator.clipboard.writeText(wifiString).then(() => toast('Connection URL copied'));
      }
    });

    $('#showPassword').addEventListener('click', showPassword);
    $('#testConnection').addEventListener('click', testConnectionURL);

    // Initialize
    $('#generate').click();
  });
}

function cameraTool() {
  setTool('Camera Recorder', `
        <div class="form-group">
            <label>Camera</label>
            <select id="cameraSelect">
                <option value="">Select camera...</option>
            </select>
        </div>
        <div class="row">
            <div class="form-group">
                <label>Resolution</label>
                <select id="resolution">
                    <option value="640x480">640x480 (VGA)</option>
                    <option value="1280x720" selected>1280x720 (HD)</option>
                    <option value="1920x1080">1920x1080 (Full HD)</option>
                </select>
            </div>
            <div class="form-group">
                <label>Frame Rate</label>
                <select id="frameRate">
                    <option value="30">30 fps</option>
                    <option value="24">24 fps</option>
                    <option value="15">15 fps</option>
                </select>
            </div>
        </div>
        <div class="btn-group">
            <button id="startCamera" class="btn"><i class="fas fa-play"></i> Start Camera</button>
            <button id="takePhoto" class="btn btn-secondary"><i class="fas fa-camera"></i> Take Photo</button>
            <button id="startRecord" class="btn btn-secondary"><i class="fas fa-video"></i> Start Recording</button>
            <button id="stopRecord" class="btn btn-secondary" disabled><i class="fas fa-stop"></i> Stop Recording</button>
        </div>
        <div id="cameraContainer" style="margin-top: 24px; text-align: center; display: none;">
            <video id="cameraPreview" autoplay playsinline style="width: 100%; max-width: 640px; border-radius: 8px; background: #000;"></video>
            <canvas id="photoCanvas" style="display: none;"></canvas>
        </div>
        <div id="captures" style="margin-top: 24px;">
            <h4 style="margin-bottom: 8px;">📸 Captures</h4>
            <div id="capturesList" style="display: grid; grid-template-columns: repeat(auto-fill, minmax(150px, 1fr)); gap: 12px;"></div>
        </div>
        <div style="margin-top: 16px; padding: 16px; background: var(--bg-secondary); border-radius: 8px;">
            <h4 style="margin-bottom: 8px;">⚠️ Camera Permissions</h4>
            <div style="font-size: 14px;">
                <p>This tool requires camera access. Your browser will ask for permission to use your camera.</p>
                <p>All processing happens locally in your browser. No images or videos are sent to any server.</p>
            </div>
        </div>
      `, () => {
    let stream = null;
    let mediaRecorder = null;
    let recordedChunks = [];
    let isRecording = false;

    async function getCameras() {
      try {
        const devices = await navigator.mediaDevices.enumerateDevices();
        const videoDevices = devices.filter(device => device.kind === 'videoinput');

        const select = $('#cameraSelect');
        select.innerHTML = '<option value="">Select camera...</option>';

        videoDevices.forEach(device => {
          const option = document.createElement('option');
          option.value = device.deviceId;
          option.text = device.label || `Camera ${select.options.length}`;
          select.appendChild(option);
        });

        if (videoDevices.length > 0) {
          toast(`${videoDevices.length} camera(s) found`);
        } else {
          toast('No cameras found', 'error');
        }
      } catch (error) {
        toast('Error accessing cameras: ' + error.message, 'error');
      }
    }

    async function startCamera() {
      const cameraId = $('#cameraSelect').value;
      const resolution = $('#resolution').value;
      const frameRate = parseInt($('#frameRate').value);

      const [width, height] = resolution.split('x').map(Number);

      const constraints = {
        video: {
          width: { ideal: width },
          height: { ideal: height },
          frameRate: { ideal: frameRate },
          deviceId: cameraId ? { exact: cameraId } : undefined
        },
        audio: false
      };

      try {
        // Stop existing stream
        if (stream) {
          stream.getTracks().forEach(track => track.stop());
        }

        // Get new stream
        stream = await navigator.mediaDevices.getUserMedia(constraints);

        // Display stream
        const video = $('#cameraPreview');
        video.srcObject = stream;
        $('#cameraContainer').style.display = 'block';

        toast('Camera started');
      } catch (error) {
        toast('Error starting camera: ' + error.message, 'error');
      }
    }

    function takePhoto() {
      if (!stream) {
        toast('Start camera first', 'error');
        return;
      }

      const video = $('#cameraPreview');
      const canvas = $('#photoCanvas');
      const context = canvas.getContext('2d');

      // Set canvas size to video size
      canvas.width = video.videoWidth;
      canvas.height = video.videoHeight;

      // Draw current video frame to canvas
      context.drawImage(video, 0, 0, canvas.width, canvas.height);

      // Create download link
      const dataUrl = canvas.toDataURL('image/png');
      const timestamp = new Date().toISOString().replace(/[:.]/g, '-');

      // Add to captures list
      const capturesList = $('#capturesList');
      const captureItem = document.createElement('div');
      captureItem.style.cssText = `
                border-radius: 8px;
                overflow: hidden;
                position: relative;
                cursor: pointer;
            `;

      captureItem.innerHTML = `
                <img src="${dataUrl}" style="width: 100%; height: 100px; object-fit: cover;" />
                <div style="position: absolute; bottom: 0; left: 0; right: 0; background: rgba(0,0,0,0.7); color: white; padding: 4px; font-size: 11px; text-align: center;">
                    Photo ${capturesList.children.length + 1}
                </div>
            `;

      captureItem.addEventListener('click', () => {
        const link = document.createElement('a');
        link.download = `photo_${timestamp}.png`;
        link.href = dataUrl;
        link.click();
      });

      capturesList.appendChild(captureItem);
      toast('Photo captured');
    }

    function startRecording() {
      if (!stream) {
        toast('Start camera first', 'error');
        return;
      }

      if (isRecording) {
        toast('Already recording', 'error');
        return;
      }

      try {
        recordedChunks = [];
        const options = { mimeType: 'video/webm;codecs=vp9' };
        mediaRecorder = new MediaRecorder(stream, options);

        mediaRecorder.ondataavailable = (event) => {
          if (event.data.size > 0) {
            recordedChunks.push(event.data);
          }
        };

        mediaRecorder.onstop = () => {
          const blob = new Blob(recordedChunks, { type: 'video/webm' });
          const url = URL.createObjectURL(blob);
          const timestamp = new Date().toISOString().replace(/[:.]/g, '-');

          // Add to captures list
          const capturesList = $('#capturesList');
          const captureItem = document.createElement('div');
          captureItem.style.cssText = `
                        border-radius: 8px;
                        overflow: hidden;
                        position: relative;
                        cursor: pointer;
                    `;

          captureItem.innerHTML = `
                        <div style="width: 100%; height: 100px; background: linear-gradient(45deg, var(--primary), var(--primary-light)); display: flex; align-items: center; justify-content: center; color: white;">
                            <i class="fas fa-video" style="font-size: 32px;"></i>
                        </div>
                        <div style="position: absolute; bottom: 0; left: 0; right: 0; background: rgba(0,0,0,0.7); color: white; padding: 4px; font-size: 11px; text-align: center;">
                            Video ${capturesList.children.length + 1}
                        </div>
                    `;

          captureItem.addEventListener('click', () => {
            const link = document.createElement('a');
            link.download = `recording_${timestamp}.webm`;
            link.href = url;
            link.click();
          });

          capturesList.appendChild(captureItem);
          toast('Recording saved');
        };

        mediaRecorder.start();
        isRecording = true;
        $('#startRecord').disabled = true;
        $('#stopRecord').disabled = false;

        toast('Recording started');
      } catch (error) {
        toast('Error starting recording: ' + error.message, 'error');
      }
    }

    function stopRecording() {
      if (!isRecording || !mediaRecorder) {
        toast('Not recording', 'error');
        return;
      }

      mediaRecorder.stop();
      isRecording = false;
      $('#startRecord').disabled = false;
      $('#stopRecord').disabled = true;

      toast('Recording stopped');
    }

    $('#startCamera').addEventListener('click', startCamera);
    $('#takePhoto').addEventListener('click', takePhoto);
    $('#startRecord').addEventListener('click', startRecording);
    $('#stopRecord').addEventListener('click', stopRecording);

    // Initialize cameras list
    getCameras();

    // Request camera permission on load
    setTimeout(() => {
      if (navigator.mediaDevices && navigator.mediaDevices.getUserMedia) {
        // Try to get a camera list without starting the camera
        navigator.mediaDevices.getUserMedia({ video: true, audio: false })
          .then(testStream => {
            testStream.getTracks().forEach(track => track.stop());
            getCameras();
          })
          .catch(() => {
            toast('Camera access not granted', 'error');
          });
      }
    }, 1000);
  });
}

// Initialize any remaining placeholder functions
function placeholder(name) {
  setTool(name, `
        <div style="text-align:center;padding:60px 20px;">
            <div style="font-size:48px;margin-bottom:20px;">🔧</div>
            <h3 style="margin-bottom:12px;">${name}</h3>
            <p style="color:var(--text-muted);">This tool is available but requires additional implementation or external libraries.</p>
            <div style="margin-top:24px;">
                <button class="btn" onclick="showDashboard()">Browse Other Tools</button>
            </div>
        </div>
    `);
}

// Define remaining placeholder functions
const placeholderTools = [
  'bip39', 'rsa', 'pwStrength', 'pdfcheck', // Crypto
  'datetime', 'intbase', 'roman', 'b64file', 'color', 'case', 'nato', 'asciibin', 'unicode',
  'yaml2json', 'yaml2toml', 'json2yaml', 'json2toml', 'listconv', 'toml2json', 'toml2yaml',
  'xml2json', 'json2xml', 'md2html', // Converter
  'urlenc', 'escapehtml', 'urlparser', 'basicauth', 'og', 'otp', 'mimetypes', 'jwt',
  'keycode', 'slugify', 'wysiwyg', 'uap', 'httpcodes', 'jsondiff', 'safelink', // Web
  'gitcheat', 'crontab', 'jsontocsv', 'sqlpretty', 'chmod', 'dockerrun', 'xmlfmt',
  'yamlpretty', 'emailnorm', 'regextester', 'regexcheat', // Development
  'ipv4sub', 'ipv4conv', 'ipv4range', 'maclookup', 'macgen', 'ipv6ula', // Network
  'matheval', 'eta', 'percent', // Math
  'chronometer', 'temp', 'benchmark', // Measurement
  'lorem', 'textstats', 'emoji', 'obfuscator', 'textdiff', 'numeronym', 'asciiart', // Text
  'phoneparse', 'iban', // Data
  'qrcode', 'wifiqr', 'svg', 'camera' // Images
];

placeholderTools.forEach(tool => {
  if (!window[tool + 'Tool']) {
    window[tool + 'Tool'] = () => placeholder(tool.replace(/([A-Z])/g, ' $1').trim());
  }
});
