<?php
class MoWebAuthnDB {
	private $userDetailsTable;
	function __construct() {
		global $wpdb;
		
		if(is_multisite()){
			$this->userDetailsTable = $wpdb->base_prefix . 'mowebAuthn_user_details';
		}else{
			$this->userDetailsTable = $wpdb->prefix . 'mowebAuthn_user_details';
		}	
	}
	function mowebauthn_plugin_activate() {
		$this->mowebauthn_generate_tables();
	}
	function mowebauthn_generate_tables() {
		require_once( ABSPATH . 'wp-admin'.DIRECTORY_SEPARATOR.'includes'.DIRECTORY_SEPARATOR.'upgrade.php' );

		global $wpdb;
		$does_table_exist = $this->check_if_table_exists();
		if(!$does_table_exist)
		{
			$tableName = $this->userDetailsTable;
			$sql       = "CREATE TABLE " . $tableName . " (
					`user_id` bigint NOT NULL,
					`mowebauthn_rpID` mediumtext NOT NULL,
					`mowebauthn_credential_ID` LONGTEXT NOT NULL, 
					`mowebauthn_credentialPublicKey` LONGTEXT NOT NULL, 
					`mowebauthn_certificateChain` LONGTEXT NOT NULL,
					`mowebauthn_certificate` LONGTEXT NOT NULL,
					`mowebauthn_signatureCounter` LONGTEXT NOT NULL,
					`mowebauthn_AAGUID` LONGTEXT NOT NULL,
					`mowebauthn_timeStamp` datetime DEFAULT now()
					);";
			dbDelta( $sql );
		}
	}
	function mowebauthn_insert_credentials( $user_id, $mowebauthn_rpID,$mowebauthn_credential_ID, $mowebauthn_credentialPublicKey,$mowebauthn_certificateChain,$mowebauthn_certificate,$mowebauthn_signatureCounter,$mowebauthn_AAGUID) {
		global $wpdb;

		$sql = 'INSERT INTO '.$this->userDetailsTable .'(user_id,mowebauthn_rpID,mowebauthn_credential_ID,mowebauthn_credentialPublicKey,mowebauthn_certificateChain,mowebauthn_certificate,mowebauthn_signatureCounter,mowebauthn_AAGUID) VALUES('.$user_id.',\''.$mowebauthn_rpID.'\',\''.$mowebauthn_credential_ID.'\', \''.$mowebauthn_credentialPublicKey.'\',\''.$mowebauthn_certificateChain.'\',\''.$mowebauthn_certificate.'\',\''.$mowebauthn_signatureCounter.'\',\''.$mowebauthn_AAGUID.'\')';
		$wpdb->query( $sql );
	}
	function mowebauthn_drop_table( $table_name ) {
		global $wpdb;
		$sql = "DROP TABLE $table_name";
		$wpdb->query( $sql );
	}
	function check_if_table_exists() {
		global $wpdb;
		$does_table_exist= $wpdb->query(
			"SHOW TABLES LIKE  '" . $this->userDetailsTable . "';"
		);
		return $does_table_exist;
	}

	function get_user_record($user_id)
	{
		global $wpdb;
		$user_column_detail = $wpdb->get_results( "SELECT mowebauthn_rpId, mowebauthn_timeStamp FROM " . $this->userDetailsTable . " WHERE user_id = " . $user_id . ";" );
		$value= empty( $user_column_detail ) ? 0 : get_object_vars( $user_column_detail[0]);
		return $value;
	}

	function get_user_detail($column_name , $user_id) {
		global $wpdb;
		$user_column_detail = $wpdb->get_results( "SELECT " . $column_name . " FROM " . $this->userDetailsTable . " WHERE user_id = " . $user_id . ";" );
		$value              = empty( $user_column_detail ) ? '' : get_object_vars( $user_column_detail[0] );
		return $value == '' ? '' : $value[ $column_name ];
	}
	function delete_user_details( $user_id ) {
		global $wpdb;
		$wpdb->query(
			"DELETE FROM " . $this->userDetailsTable . "
				 WHERE user_id = " . $user_id
		);
		return;
	}
	
}
?>