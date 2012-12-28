package com.yubico.yubitotp;

import android.os.Bundle;
import android.app.Activity;
import android.view.Menu;

public class TotpActivity extends Activity {

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

}
