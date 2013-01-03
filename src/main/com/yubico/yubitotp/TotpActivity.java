package com.yubico.yubitotp;

import java.io.IOException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.commons.codec.binary.Base32;

import android.app.Activity;
import android.app.AlertDialog;
import android.app.PendingIntent;
import android.content.ActivityNotFoundException;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.IntentFilter;
import android.net.Uri;
import android.nfc.NfcAdapter;
import android.nfc.Tag;
import android.nfc.tech.IsoDep;
import android.os.Bundle;
import android.util.Log;
import android.view.Menu;
import android.view.View;
import android.widget.Toast;

import com.yubico.base.Configurator;

public class TotpActivity extends Activity {
	
	private static final int SCAN_BARCODE = 0;
	
	private static final String logTag = "yubitotp";

	// is 16 the max length?
	private static final Pattern secretPattern = Pattern.compile("^otpauth://totp/.*?secret=([a-z2-7=]{0,32})$", Pattern.CASE_INSENSITIVE);

	private static final byte[] selectCommand = {0x00, (byte) 0xA4, 0x04, 0x00, 0x07, (byte) 0xA0, 0x00, 0x00, 0x05, 0x27, 0x20, 0x01, 0x00};
	private static final byte[] totpCommand = {0x00, 0x01, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00};
	private static final byte[] programCommand = {0x00, 0x01, 0x00};
	
	private static final int totp_step = 30;
	
	private static final byte SLOT_CONFIG = 0x01;
	private static final byte SLOT_CONFIG2 = 0x03;
	
	private static final byte SLOT_CHAL_HMAC1 = 0x30;
	private static final byte SLOT_CHAL_HMAC2 = 0x38;
	
	private AlertDialog swipeDialog;
	
	private static final int STATE_PROGRAMMING = 0;
	private static final int STATE_CHALLENGE = 1;
	
	@Override
	protected void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);
		setContentView(R.layout.activity_totp);
	}

	@Override
	public boolean onCreateOptionsMenu(Menu menu) {
		// Inflate the menu; this adds items to the action bar if it is present.
		getMenuInflater().inflate(R.menu.activity_totp, menu);
		return true;
	}

	public void onProgramClick(View view)  
	{  
	    Toast.makeText(this, "Button clicked!", Toast.LENGTH_SHORT).show();  
		Intent intent = new Intent(
				"com.google.zxing.client.android.SCAN");
		intent.setPackage("com.google.zxing.client.android");
		intent.putExtra("SCAN_MODE", "QR_CODE_MODE");
		intent.putExtra("SAVE_HISTORY", false);
		
		try {
			startActivityForResult(intent, SCAN_BARCODE);

		} catch (ActivityNotFoundException e) {
			barcodeScannerNotInstalled(
					getString(R.string.warning),
					getString(R.string.barcode_scanner_not_found),
					getString(R.string.yes),
					getString(R.string.no));
		}
		return;
	}
	
	public void onActivityResult(int requestCode, int resultCode, Intent intent) {
		if (requestCode == SCAN_BARCODE) {
			if (resultCode == RESULT_OK) {
				String content = intent.getStringExtra("SCAN_RESULT");
				Matcher matcher = secretPattern.matcher(content);
				if(!matcher.matches()) {
					Toast.makeText(this, R.string.invalid_barcode, Toast.LENGTH_LONG).show();
					return;
				}
				final String secret = matcher.group(1);
				AlertDialog.Builder slotDialog = new AlertDialog.Builder(this);
				slotDialog.setTitle(R.string.program_slot);
				slotDialog.setItems(R.array.slots, new DialogInterface.OnClickListener() {
					public void onClick(DialogInterface dialog, int which) {
						dialog.dismiss();
						programYubiKey(which + 1, secret);
					}
				});
				slotDialog.show();
			} else {
				Toast.makeText(this, R.string.scan_failed, Toast.LENGTH_LONG).show();
				return;
			}
		}
	}
	
	private void programYubiKey(int slot, String secret) {
		Log.i(logTag, "Programming slot " + slot);
		AlertDialog.Builder programDialog = new AlertDialog.Builder(this);
		programDialog.setTitle(R.string.programming);
		programDialog.setMessage(R.string.swipe_and_hold);
		programDialog.setOnCancelListener(new DialogInterface.OnCancelListener() {
			public void onCancel(DialogInterface dialog) {
				disableDispatch();
			}
		});
		swipeDialog = programDialog.show();
		enableDispatch(STATE_PROGRAMMING, slot, secret);
	}
	
	private void enableDispatch(int state, int slot, String secret) {
		Intent newIntent = new Intent(this, getClass());
		newIntent.addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP);
		newIntent.putExtra("state", state);
		newIntent.putExtra("slot", slot);
		if(secret != null) {
			newIntent.putExtra("secret", secret);
		}
    	PendingIntent pendingIntent = PendingIntent.getActivity(
    			this, 0, newIntent, 0);
    	
    	IntentFilter iso = new IntentFilter(NfcAdapter.ACTION_TECH_DISCOVERED);
    	
    	// register for foreground dispatch so we'll receive tags according to our intent filters
    	NfcAdapter.getDefaultAdapter(this).enableForegroundDispatch(
    			this, pendingIntent, new IntentFilter[] {iso},
    			new String[][] { new String[] { IsoDep.class.getName() } }
    			);
	}
	
	private void disableDispatch() {
		NfcAdapter.getDefaultAdapter(this).disableForegroundDispatch(this);
	}

	public void onNewIntent(Intent intent) {
		int state = intent.getIntExtra("state", -1);
		int slot = intent.getIntExtra("slot", -1);
		if(state >= 0) {
			Tag tag = intent.getParcelableExtra(NfcAdapter.EXTRA_TAG);
			if(tag != null) {
				IsoDep isoTag = IsoDep.get(tag);
				try {
					isoTag.connect();
					byte[] resp = isoTag.transceive(selectCommand);
					int length = resp.length;
					if(resp[length - 2] == (byte)0x90 && resp[length - 1] == 0x00) {
						switch(state) {
						case STATE_PROGRAMMING:
							doProgramYubiKey(isoTag, slot, intent.getStringExtra("secret"));
							break;
						case STATE_CHALLENGE:
							// TODO: do something
							break;
						default:
						}
					} else {
						
					}
					isoTag.close();
					swipeDialog.dismiss();
				} catch (IOException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
			}
		}
	}

	private void doProgramYubiKey(IsoDep isoTag, int slot, String secret) throws IOException {
		Log.i(logTag, "programming slot " + slot + " with secret " + secret);
		Base32 base32 = new Base32();
		byte[] decoded = base32.decode(secret.toUpperCase());
		byte[] key = new byte[20];
		System.arraycopy(decoded, 0, key, 0, decoded.length);

		byte[] apdu = new byte[64];
		apdu[1] = 0x01;
		apdu[2] = slot == 1 ? SLOT_CONFIG : SLOT_CONFIG2;
		
		Configurator cfg = new Configurator();
		cfg.setKey(Configurator.HMAC_SHA1_MODE, key);
		cfg.setCfgFlags((byte) (Configurator.CFGFLAG_CHAL_HMAC | Configurator.CFGFLAG_HMAC_LT64));
		cfg.setTktFlags(Configurator.TKTFLAG_CHAL_RESP);
		cfg.setExtFlags((byte) (Configurator.EXTFLAG_SERIAL_API_VISIBLE | Configurator.EXTFLAG_ALLOW_UPDATE));
		byte[] structure = cfg.getConfigStructure();
		apdu[4] = (byte) structure.length;
		System.arraycopy(structure, 0, apdu, 5, structure.length);
		
		byte[] resp = isoTag.transceive(apdu);
		String rApdu = new String();
		for(byte b : resp) {
			rApdu += String.format("0x%x ", b);
		}
		Toast.makeText(this, "response was: " + rApdu, Toast.LENGTH_LONG).show();
	}

	private void barcodeScannerNotInstalled(String stringTitle,
			String stringMessage, String stringButtonYes, String stringButtonNo) {
		AlertDialog.Builder downloadDialog = new AlertDialog.Builder(this);
		downloadDialog.setTitle(stringTitle);
		downloadDialog.setMessage(stringMessage);
		downloadDialog.setPositiveButton(stringButtonYes,
				new DialogInterface.OnClickListener() {
					public void onClick(DialogInterface dialogInterface, int i) {
						Uri uri = Uri.parse("market://search?q=pname:"
								+ "com.google.zxing.client.android");
						Intent intent = new Intent(Intent.ACTION_VIEW, uri);
						TotpActivity.this.startActivity(intent);
					}
				});
		downloadDialog.setNegativeButton(stringButtonNo,
				new DialogInterface.OnClickListener() {
					public void onClick(DialogInterface dialogInterface, int i) {
					}
				});
		downloadDialog.show();
	}
}
