/* GRS Security - pagine di amministrazione. */
( function () {
	'use strict';

	var cfg = window.grsSecurity || {};

	document.addEventListener( 'click', function ( event ) {
		var button = event.target.closest ? event.target.closest( '[data-grs-confirm]' ) : null;
		if ( ! button || 'BUTTON' !== button.tagName ) {
			return;
		}
		var type = button.getAttribute( 'data-grs-confirm' );
		var message = 'salts' === type ? cfg.confirmSalts : cfg.confirmRevert;
		if ( message && ! window.confirm( message ) ) {
			event.preventDefault();
		}
	} );

	var bulk = document.getElementById( 'grs-sec-bulk' );
	if ( bulk ) {
		bulk.addEventListener( 'submit', function ( event ) {
			if ( event.submitter && event.submitter.getAttribute( 'form' ) ) {
				return;
			}
			var salts = bulk.querySelector( 'input[data-grs-confirm="salts"]:checked' );
			if ( salts && cfg.confirmSalts && ! window.confirm( cfg.confirmSalts ) ) {
				event.preventDefault();
			}
		} );
	}
}() );
