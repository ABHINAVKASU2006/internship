<?php
require_once 'phpqrcode/phpqrcode/qrlib.php';


$qrDir = 'qrcodes/';
if (!file_exists($qrDir)) {
    mkdir($qrDir, 0755, true); // Create the folder if it doesn't exist
}

$dataArray = ['0409495298628610', '8457601788976457'];

foreach ($dataArray as $data) {
    $filename = $qrDir . $data . '.png';

    if (!file_exists($filename)) {
        QRcode::png($data, $filename, QR_ECLEVEL_L, 4);
    }

    echo "
    <div style='display:inline-block; text-align:center; margin:10px; border:1px solid #ccc; padding:10px; border-radius:10px;'>
        <p>QR Code for <strong>$data</strong></p>
        <img src='$filename' alt='QR Code for $data' style='width:150px; height:150px;'><br>
        <div style='background:#e7f4e4; padding:5px;'>$data</div>
    </div>
    ";
}
?>
