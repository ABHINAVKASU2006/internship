<?php
// Enable error reporting for debugging
ini_set('display_errors', 1);
error_reporting(E_ALL);

// Include the phpqrcode library (adjust path if needed)
require_once('phpqrcode/phpqrcode/qrlib.php');

// Function to generate a random 16-digit numeric string
function generateRandomCode() {
    $code = '';
    for ($i = 0; $i < 16; $i++) {
        $code .= (string)rand(0, 9);
    }
    return $code;
}

// Get the number of QR codes requested (default 0)
$qrCount = isset($_POST['qrCount']) ? (int)$_POST['qrCount'] : 0;
$qrCodes = [];
$error = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if ($qrCount < 1 || $qrCount > 100) {
        $error = "Please enter a number between 1 and 100.";
    } else {
        for ($i = 0; $i < $qrCount; $i++) {
            $code = generateRandomCode();

            // Capture PNG output in memory buffer
            ob_start();
            QRcode::png($code, null, QR_ECLEVEL_L, 6, 2);
            $imageString = ob_get_contents();
            ob_end_clean();

            $qrCodes[] = [
                'code' => $code,
                'image' => base64_encode($imageString)
            ];
        }
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>16-Digit QR Code Generator</title>
    <style>
        :root {
            --primary: #38bdf8;        /* Light Blue */
            --secondary: #e0f2fe;      /* Very light blue */
            --accent: #fbbf24;         /* Soft yellow accent */
            --teal: #0ea5e9;           /* Deeper blue for contrast */
            --dark: #1e293b;           /* Dark blue-gray for text */
            --white: #ffffff;
            --light-gray: #f8fafc;
            --shadow: 0 4px 12px rgba(56, 189, 248, 0.10);
        }
        body {
            font-family: Arial, sans-serif;
            background: var(--light-gray);
            color: var(--dark);
            padding: 20px;
        }
        .container {
            max-width: 960px;
            margin: 0 auto;
            background: var(--white);
            padding: 30px;
            border-radius: 12px;
            box-shadow: var(--shadow);
        }
        h1 {
            color: var(--primary);
            text-align: center;
            margin-bottom: 25px;
        }
        form {
            display: flex;
            justify-content: center;
            align-items: center;
            gap: 15px;
            margin-bottom: 20px;
            flex-wrap: wrap;
        }
        input[type="number"] {
            padding: 10px 15px;
            font-size: 16px;
            border: 2px solid var(--teal);
            border-radius: 8px;
            width: 120px;
            text-align: center;
        }
        button {
            background: var(--primary);
            color: var(--white);
            border: none;
            padding: 12px 28px;
            font-size: 16px;
            border-radius: 8px;
            cursor: pointer;
            transition: background-color 0.3s ease;
        }
        button:hover {
            background: var(--teal);
        }
        .error {
            color: #e57373;
            text-align: center;
            margin-bottom: 15px;
            font-weight: bold;
        }
        .qr-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(180px, 1fr));
            gap: 25px;
        }
        .qr-card {
            background: var(--secondary);
            border-radius: 12px;
            padding: 15px;
            box-shadow: 0 3px 10px rgba(56, 189, 248, 0.08);
            text-align: center;
            transition: transform 0.2s ease;
        }
        .qr-card:hover {
            transform: translateY(-5px);
        }
        .qr-image {
            width: 150px;
            height: 150px;
            margin: 0 auto 12px auto;
            border: 1px solid var(--teal);
            border-radius: 8px;
            background: var(--white);
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .qr-image img {
            max-width: 100%;
            max-height: 100%;
        }
        .qr-code-text {
            font-family: monospace;
            font-size: 16px;
            color: var(--dark);
            word-break: break-word;
            font-weight: 600;
            user-select: all;
        }
        .note {
            text-align: center;
            font-style: italic;
            color: #777;
            margin-top: 10px;
        }
        @media (max-width: 600px) {
            .qr-grid {
                grid-template-columns: repeat(auto-fill, minmax(140px, 1fr));
                gap: 15px;
            }
            .qr-image {
                width: 120px;
                height: 120px;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>16-Digit QR Code Generator</h1>
        <?php if ($error): ?>
            <div class="error"><?= htmlspecialchars($error) ?></div>
        <?php endif; ?>
        <form method="post" novalidate>
            <input type="number" name="qrCount" min="1" max="100" required
                   value="<?= htmlspecialchars($qrCount) ?>"
                   placeholder="Number of QR Codes" />
            <button type="submit">Generate</button>
        </form>
        <?php if (!empty($qrCodes)): ?>
            <div class="qr-grid">
                <?php foreach ($qrCodes as $qr): ?>
                    <div class="qr-card">
                        <div class="qr-image">
                            <img src="data:image/png;base64,<?= $qr['image'] ?>" alt="QR Code">
                        </div>
                       <div class="qr-code-text"><?= htmlspecialchars($qr['code']) ?></div>
                        <div class="note">Scan to see this 16-digit code</div>
                    </div>
                <?php endforeach; ?>
            </div>
        <?php else: ?>
            <div class="note">Enter the number of QR codes you want to generate (1-100) and click Generate.</div>
        <?php endif; ?>
    </div>
</body>
</html>
