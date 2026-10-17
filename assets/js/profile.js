/* GRS Security - QR code della verifica in due passaggi (generato nel browser, il segreto non lascia la pagina). */
( function () {
	'use strict';

	var box = document.querySelector( '.grs-sec-qr[data-otpauth]' );
	if ( ! box || 'function' !== typeof window.qrcode ) {
		return;
	}
	try {
		var qr = window.qrcode( 0, 'M' );
		qr.addData( box.getAttribute( 'data-otpauth' ) );
		qr.make();
		box.innerHTML = qr.createSvgTag( { cellSize: 5, margin: 20, scalable: false } );
	} catch ( e ) {
		box.textContent = '';
	}
}() );
