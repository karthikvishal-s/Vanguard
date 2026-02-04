import React, { useState, useRef } from 'react';
import { QRCodeCanvas } from 'qrcode.react';

const QREncoder = () => {
    const [text, setText] = useState('');
    const qrRef = useRef(null);

    const downloadQR = () => {
        if (!qrRef.current) return;
        const canvas = qrRef.current.querySelector('canvas');
        if (!canvas) return;

        const url = canvas.toDataURL("image/png");
        const a = document.createElement("a");
        a.href = url;
        a.download = "vanguard_qr_code.png";
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
    };

    return (
        <div className="flex flex-col items-center gap-6 p-6 bg-black bg-opacity-30 border border-gray-700 rounded">
            <div className="w-full">
                <label className="block text-gray-400 text-xs font-bold mb-2 tracking-widest uppercase">
                    Data to Encode
                </label>
                <textarea
                    className="input-field w-full h-32 font-mono text-sm"
                    placeholder="ENTER DATA TO ENCODE..."
                    value={text}
                    onChange={(e) => setText(e.target.value)}
                />
            </div>

            <div className="p-4 bg-white rounded" ref={qrRef}>
                <QRCodeCanvas
                    value={text || "WAITING FOR DATA"}
                    size={200}
                    level={"H"}
                    includeMargin={true}
                />
            </div>

            <div className="w-full flex justify-center">
                <button
                    onClick={downloadQR}
                    disabled={!text}
                    className="btn btn-primary w-full max-w-xs"
                >
                    DOWNLOAD PNG
                </button>
            </div>

            <div className="text-center text-xs text-gray-500 font-mono">
                {text ? 'QR CODE GENERATED SUCCESSFULLY' : 'WAITING FOR INPUT...'}
            </div>
        </div>
    );
};

export default QREncoder;
