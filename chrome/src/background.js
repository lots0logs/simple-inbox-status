/*
 * background.js
 *
 * Copyright © 2017 Dustin Falgout <dustin@falgout.us>
 *
 * This file is part of Simple Inbox Status.
 *
 * Simple Inbox Status is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * Simple Inbox Status is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * The following additional terms are in effect as per Section 7 of the license:
 *
 * The preservation of all legal notices and author attributions in
 * the material or in the Appropriate Legal Notices displayed
 * by works containing it is required.
 *
 * You should have received a copy of the GNU General Public License
 * along with Simple Inbox Status; If not, see <http://www.gnu.org/licenses/>.
 */

/**
 * Binds `this` to class instance, `context`, for all of the instances methods.
 *
 * @example At the end of the instance's constructor method: `return bindThis( this );`
 *
 * @param {object} context An ES6 class instance with at least one method.
 *
 * @return {object} `context` with `this` bound to it for all of its methods.
 */
function bind_this( context ) {
	for ( let obj = context; obj; obj = Object.getPrototypeOf( obj ) ) {
		// Stop once we've traveled beyond our own classes in the inheritance chain.
		if ( 'Object' === obj.constructor.name ) {
			break;
		}

		for ( const method of Object.getOwnPropertyNames( obj ) ) {
			if ( 'function' === typeof context[method] && 'constructor' !== method ) {
				context[method] = context[method].bind( context );
			}
		}
	}

	return context;
}


/**
 * @typedef {Object} AuthResponse
 * @property {string} accessToken
 * @property {string} idToken
 */


class SimpleInboxStatus {

	constructor() {
		this.is_authorized = false;
		this.access_token  = null;
		this.id_token      = null;
		this.current_nonce = null;
		this.user          = {};

		this.manifest         = chrome.runtime.getManifest();
		this.mail_folders_url = `${this.manifest.oauth2.api_endpoint}/me/MailFolders`;

		return bind_this( this );
	}

	initialize() {
		const defaults = {
			access_token:  this.access_token,
			id_token:      this.id_token,
			user:          this.user,
			current_nonce: this.current_nonce,
			is_authorized: this.is_authorized,
		};

		chrome.storage.sync.get( defaults, data => {
			this.access_token  = data.access_token;
			this.id_token      = data.id_token;
			this.is_authorized = data.is_authorized;
			this.current_nonce = data.current_nonce;
			this.user          = data.user;

			chrome.browserAction.onClicked.addListener( tab => this.onClicked( tab ) );
			chrome.browserAction.setBadgeBackgroundColor( { color: '#f92c8b' } );

			chrome.alarms.onAlarm.addListener( alarm => this.fetch_message_count( alarm ) );
			chrome.alarms.create( 'fetch_message_count', {when: Date.now(), periodInMinutes: 5 } );
		} );
	}

	authorize( interactive = true, recursive = false ) {
		const redirect_url = chrome.identity.getRedirectURL( '/callback' );
		const scope        = this.manifest.oauth2.scopes.join( ' ' );
		const query        = {
			client_id: this.manifest.oauth2.client_id,
			redirect_url: encodeURIComponent( redirect_url ),
			response_type: 'id_token token',
			scope: encodeURIComponent( scope ),
			response_mode: 'fragment',
			nonce: this.create_nonce(),
		};

		if ( ! interactive ) {
			Object.assign( query, {
				prompt: 'none',
				domain_hint: this.user.domain_type,
				login_hint: this.user.signin_name,
			});
		}

		this.current_nonce = query['nonce'];

		let request_url = this.manifest.oauth2.auth_url;

		for ( const key of Object.keys( query ) ) {
			request_url += `${key}=${query[ key ]}&`;
		}

		const request_details = { url: request_url, interactive: interactive };

		chrome.identity.launchWebAuthFlow( request_details, result => {
			if ( chrome.runtime.lastError ) {
				console.error( chrome.runtime.lastError );
				return;
			}

			result = this.parse_auth_response( result );

			if ( ! this.validate_id_token( result.id_token ) ) {
				console.error( 'Id token validation failed!' );
				return;
			}

			this.id_token      = result.id_token;
			this.access_token  = result.access_token;
			this.is_authorized = true;

			console.log(this);

			chrome.storage.sync.set( {
				access_token: this.access_token,
				id_token: this.id_token,
				user: this.user,
				current_nonce: this.current_nonce,
				is_authorized: this.is_authorized,
			} );

			this.fetch_message_count();
		});
	}

	calculate_total_unread_messages( mail_folders ) {
		let count = 0;

		for ( const folder of mail_folders ) {
			count += folder['UnreadItemCount'];
		}

		return count;
	}

	create_nonce() {
		const parts = new Uint16Array( 8 );
		let result  = '';

		crypto.getRandomValues( parts );

		function s4( num ) {
			let ret = num.toString( 16 );

			while ( ret.length < 4 ) {
				ret = '0' + ret;
			}

			return ret;
		}

		for ( const [index, part] of parts.entries() ) {
			if ( index > 1 && index < 6 ) {
				result += '-';
			}

			result += s4( part );
		}

		return result;
	}

	async fetch_message_count() {
		if ( ! this.is_authorized ) {
			return;
		}

		let response = await this.make_remote_request( this.mail_folders_url );

		if ( ! response.ok && response.status < 500 ) {
			// Token is expired. Re-authorize.
			const interactive = false;

			this.authorize( interactive );

			response = await this.make_remote_request( this.mail_folders_url );
		}

		if ( ! response.ok ) {
			console.error( 'Fetch message count failed!' );
			console.log(response);
			return;
		}

		response = await response.json();

		const count = this.calculate_total_unread_messages( response['value'] );

		this.update_status_badge( count );
	}

	async make_remote_request( url, body = null ) {
		const request_info = {
			credentials: 'include',
			method: 'GET',
			headers: new Headers({
				'Authorization': `Bearer ${this.access_token}`,
				'Accept': 'application/json',
			}),
		};

		if ( null !== body ) {
			request_info.method = 'POST';
			request_info.body   = body;
		}

		return fetch( url, request_info );
	}

	onClicked() {
		if ( this.is_authorized ) {
			window.open( 'https://outlook.com/' );
			return;
		}

		this.authorize();
	}

	/**
	 *
	 * @param response
	 * @return {AuthResponse}
	 */
	parse_auth_response( response ) {
		const params = response.substring( response.indexOf( '#' ) + 1 ).split('&');
		const result = {};

		params.forEach( param => {
			param = param.split('=');
			result[ param[0] ] = param[1];
		});

		return result;
	}

	update_status_badge( count ) {
		let text = count > 0 ? count.toString() : '';

		if ( count > 9 ) {
			text = '9+';
		}

		chrome.browserAction.setBadgeText( {text: text} );
	}

	validate_id_token( token ) {
		// Per Azure docs (and OpenID spec), we MUST validate
		// the ID token before using it. However, full validation
		// of the signature currently requires a server-side component
		// to fetch the public signing keys from Azure. This sample will
		// skip that part (technically violating the OpenID spec) and do
		// minimal validation

		if ( ! token || ! token.length ) {
			return false;
		}

		// JWT is in three parts separated by periods: '.'
		const token_parts = token.split( '.' );

		if ( token_parts.length !== 3 ){
			return false;
		}

		// Decode the token
		const decoded = jwt_decode( token );

		// Check the nonce
		if ( decoded.nonce !== this.current_nonce ) {
			return false;
		}

		// Check the audience
		if ( decoded.aud !== this.manifest.oauth2.client_id ) {
			return false;
		}

		// Check the issuer
		// Should be https://login.microsoftonline.com/{tenantid}/v2.0
		if ( decoded.iss !== `https://login.microsoftonline.com/${decoded.tid}/v2.0` ) {
			return false;
		}

		// Check the valid dates
		const now = new Date();

		// To allow for slight inconsistencies in system clocks, adjust by 5 minutes
		const notBefore = new Date( (decoded.nbf - 300) * 1000 );
		const expires   = new Date( (decoded.exp + 300) * 1000 );

		if ( now < notBefore || now > expires ) {
			return false;
		}

		// Now that we've passed our checks, save the bits of data
		// we need from the token.
		this.user.display_name = decoded.name;
		this.user.signin_name  = decoded.preferred_username;

		// Per the docs at:
		// https://azure.microsoft.com/en-us/documentation/articles/active-directory-v2-protocols-implicit/#send-the-sign-in-request
		// Check if this is a consumer account so we can set domain_hint properly
		this.user.domain_type =
			decoded.tid === '9188040d-6c67-4c5b-b112-36a304b66dad' ? 'consumers' : 'organizations';

		return true;
	}
}


const extension = new SimpleInboxStatus();

extension.initialize();
