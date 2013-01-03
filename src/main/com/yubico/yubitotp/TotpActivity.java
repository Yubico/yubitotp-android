package com.yubico.yubitotp;

import java.io.IOException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.commons.codec.binary.Base32;

import android.app.Activity;
import android.app.AlertDialog;
import android.app.PendingIntent;
import android.content.ActivityNotFoundException;
import android.content.ClipData;
import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.IntentFilter;
import android.net.Uri;
import android.nfc.NfcAdapter;
import android.nfc.Tag;
import android.nfc.tech.IsoDep;
import android.os.Bundle;
import android.content.ClipboardManager;
import android.util.Log;
import android.view.Menu;
import android.view.View;
import android.widget.TextView;
import android.widget.Toast;

import com.yubico.base.Configurator;

public class TotpActivity extends Activity {
	
	private static final int SCAN_BARCODE = 0;
	
	private static final String logTag = "yubitotp";

	// is 16 the max length?
	private static final Pattern secretPattern = Pattern.compile("^otpauth://totp/.*?secret=([a-z2-7=]{0,32})$", Pattern.CASE_INSENSITIVE);

	private static final byte[] selectCommand = {0x00, (byte) 0xA4, 0x04, 0x00, 0x07, (byte) 0xA0, 0x00, 0x00, 0x05, 0x27, 0x20, 0x01, 0x00};
	private static final byte[] totpCommand = {0x00, 0x01, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00};
	
	private static final int totp_step = 30;
	
	private static final byte SLOT_CONFIG = 0x01;
	private static final byte SLOT_CONFIG2 = 0x03;
	
	private static final byte SLOT_CHAL_HMAC1 = 0x30;
	private static final byte SLOT_CHAL_HMAC2 = 0x38;
	
	private AlertDialog swipeDialog;
	
	private static final int STATE_PROGRAMMING = 0;
	private static final int STATE_CHALLENGE = 1;
	
	private PendingIntent tagIntent;
	
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

	public void onProgramClick(View view) {  
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
		if(swipeDialog != null) {
			swipeDialog.cancel();
		}
		swipeDialog = programDialog.show();
		enableDispatch(STATE_PROGRAMMING, slot, secret);
	}
	
	private void enableDispatch(int state, int slot, String secret) {
		Intent intent = new Intent(this, getClass());
		intent.addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP);
		intent.putExtra("state", state);
		intent.putExtra("slot", slot);
		if(secret != null) {
			intent.putExtra("secret", secret);
		} else {
			intent.removeExtra("secret");
		}
    	tagIntent = PendingIntent.getActivity(
    			this, 0, intent, 0);
    	
    	IntentFilter iso = new IntentFilter(NfcAdapter.ACTION_TECH_DISCOVERED);
    	
    	// register for foreground dispatch so we'll receive tags according to our intent filters
    	NfcAdapter.getDefaultAdapter(this).enableForegroundDispatch(
    			this, tagIntent, new IntentFilter[] {iso},
    			new String[][] { new String[] { IsoDep.class.getName() } }
    			);
	}
	
	private void disableDispatch() {
		Log.i(logTag, "Disabling dispatch.");
		if(tagIntent != null) {
			tagIntent.cancel();
			tagIntent = null;
		}
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
					Log.i(logTag, "state is " + state + " and slot is " + slot);
					isoTag.connect();
					byte[] resp = isoTag.transceive(selectCommand);
					int length = resp.length;
					if(resp[length - 2] == (byte)0x90 && resp[length - 1] == 0x00) {
						switch(state) {
						case STATE_PROGRAMMING:
							doProgramYubiKey(isoTag, slot, intent.getStringExtra("secret"));
							break;
						case STATE_CHALLENGE:
							doChallengeYubiKey(isoTag, slot);
							break;
						default:
						}
					} else {
						
					}
					isoTag.close();
					// must be cancel to run the onCancel listener
				} catch (IOException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
				swipeDialog.cancel();
				swipeDialog = null;
			}
		}
	}

	private void doChallengeYubiKey(IsoDep isoTag, int slot) throws IOException {
		long time = System.currentTimeMillis() / 1000 / totp_step;
		byte apdu[] = new byte[totpCommand.length + 4];
		System.arraycopy(totpCommand, 0, apdu, 0, totpCommand.length);
		
		switch(slot) {
		case 1:
			apdu[2] = SLOT_CHAL_HMAC1;
			break;
		case 2:
			apdu[2] = SLOT_CHAL_HMAC2;
			break;
		}
		
		apdu[totpCommand.length] = (byte) (time >> 24);
		apdu[totpCommand.length + 1] = (byte) (time >> 16);
		apdu[totpCommand.length + 2] = (byte) (time >> 8);
		apdu[totpCommand.length + 3] = (byte) time;
		
		String dApdu = new String();
		for(byte b : apdu) {
			dApdu += String.format("0x%x ", b);
		}
		Log.i(logTag, "challenge for slot " + slot + " with apdu: " + dApdu);
			
		byte[] totpApdu = isoTag.transceive(apdu);
		if(totpApdu.length == 22 && totpApdu[20] == (byte)0x90 && totpApdu[21] == 0x00) {
			int offset = totpApdu[19] & 0xf;
			int code = ((totpApdu[offset++] & 0x7f) << 24) |
					((totpApdu[offset++] & 0xff) << 16) |
					((totpApdu[offset++] & 0xff) << 8) |
					((totpApdu[offset++] & 0xff));
			String totp = String.format("%06d", code % 1000000);
			showOtpDialog(totp);
		} else {
			Toast.makeText(this, R.string.totp_failed, Toast.LENGTH_LONG).show();
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
		if(resp[resp.length - 2] == (byte)0x90 && resp[resp.length - 1] == 0x00) {
			Toast.makeText(this, this.getString(R.string.prog_success, slot), Toast.LENGTH_LONG).show();
		} else {
			Toast.makeText(this, R.string.prog_fail, Toast.LENGTH_LONG).show();
		}
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
	
	public void onTotp1Click(View view) {
		challengeYubiKey(1);
	}
	
	public void onTotp2Click(View view) {
		challengeYubiKey(2);
	}

	private void challengeYubiKey(int slot) {
		Log.i(logTag, "challenge for slot " + slot);
		AlertDialog.Builder challengeDialog = new AlertDialog.Builder(this);
		challengeDialog.setTitle(R.string.challenging);
		challengeDialog.setMessage(R.string.swipe);
		challengeDialog.setOnCancelListener(new DialogInterface.OnCancelListener() {
			public void onCancel(DialogInterface dialog) {
				disableDispatch();
			}
		});
		if(swipeDialog != null) {
			swipeDialog.cancel();
		}
		swipeDialog = challengeDialog.show();
		enableDispatch(STATE_CHALLENGE, slot, null);
	}

	private void showOtpDialog(final String totp) {
		AlertDialog.Builder otpDialog = new AlertDialog.Builder(this);
		TextView input = (TextView) TextView.inflate(this,
				R.layout.otp_display, null);
		input.setText(totp);
		otpDialog.setView(input);
		
		otpDialog.setTitle(R.string.totp);
		otpDialog.setPositiveButton(R.string.ok, new DialogInterface.OnClickListener() {
			public void onClick(DialogInterface dialog, int which) {
				dialog.dismiss();
			}
		});
		otpDialog.setNegativeButton(R.string.copy, new DialogInterface.OnClickListener() {
			public void onClick(DialogInterface dialog, int which) {
				ClipboardManager clipboard = (ClipboardManager) TotpActivity.this.getSystemService(Context.CLIPBOARD_SERVICE);
				clipboard.setPrimaryClip(ClipData.newPlainText(TotpActivity.this.getText(R.string.clip_label), totp));
				Toast.makeText(TotpActivity.this, R.string.copied, Toast.LENGTH_SHORT).show();
				dialog.dismiss();
			}
		});
		otpDialog.show();
	}
}
