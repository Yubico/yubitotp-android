/* Copyright (c) 2012-2013, Yubico AB.  All rights reserved.

   Redistribution and use in source and binary forms, with or without
   modification, are permitted provided that the following conditions
   are met:

   * Redistributions of source code must retain the above copyright
     notice, this list of conditions and the following disclaimer.

   * Redistributions in binary form must reproduce the above copyright
     notice, this list of conditions and the following
     disclaimer in the documentation and/or other materials provided
     with the distribution.

   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND
   CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
   INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
   MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
   DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS
   BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
   EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
   TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
   ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR
   TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
   THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
   SUCH DAMAGE.

*/

package com.yubico.yubitotp;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.ActivityNotFoundException;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager.NameNotFoundException;
import android.net.Uri;
import android.os.Bundle;
import android.util.Log;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.widget.TextView;
import android.widget.Toast;

public class TotpActivity extends Activity {
	
	private static final int SCAN_BARCODE = 0;
	private static final int PROGRAM = 1;
	private static final int TOTP = 2;

	private static final String logTag = "yubitotp";

	// is 16 the max length?
	private static final Pattern secretPattern = Pattern.compile("^otpauth://totp/.*?secret=([a-z2-7=]{0,32})$", Pattern.CASE_INSENSITIVE);

	
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
	
	@Override
	public boolean onOptionsItemSelected(MenuItem item) {
		if(item.getItemId() == R.id.menu_about) {
			try {
				PackageInfo packageInfo = getPackageManager().getPackageInfo(getPackageName(), 0);
				AlertDialog.Builder aboutDialog = new AlertDialog.Builder(this);
				aboutDialog.setTitle(R.string.about);
				aboutDialog.setMessage(getText(R.string.version) + " " + packageInfo.versionName);
				aboutDialog.setPositiveButton(android.R.string.ok, new DialogInterface.OnClickListener() {
					public void onClick(DialogInterface dialog, int which) {
						dialog.dismiss();
					}
				});
				aboutDialog.show();
			} catch (NameNotFoundException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
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
		} else if(requestCode == PROGRAM) {
			if (resultCode == RESULT_OK) {
				Toast.makeText(this, R.string.prog_success, Toast.LENGTH_LONG).show();
			}
		} else if(requestCode == TOTP) {
			if (resultCode == RESULT_OK) {
				String totp = intent.getStringExtra("totp");
				if(totp != null) {
					showOtpDialog(totp);
				}
			}
		}
	}
	
	private void programYubiKey(int slot, String secret) {
		Log.i(logTag, "Programming slot " + slot);
		Intent programIntent = new Intent(this, TotpGenerator.class);
		programIntent.putExtra("secret", secret);
		this.startActivityForResult(programIntent, PROGRAM);
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
		Intent totpIntent = new Intent(this, TotpGenerator.class);
		totpIntent.putExtra("slot", slot);
		this.startActivityForResult(totpIntent, TOTP);
	}
	
	private void showOtpDialog(final String totp) {
		AlertDialog.Builder otpDialog = new AlertDialog.Builder(this);
		TextView input = (TextView) TextView.inflate(this,
				R.layout.otp_display, null);
		input.setText(totp);
		otpDialog.setView(input);

		otpDialog.setTitle(R.string.totp);
		otpDialog.setPositiveButton(android.R.string.ok, new DialogInterface.OnClickListener() {
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
