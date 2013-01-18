package com.yubico.yubitotp;

import android.app.AlarmManager;
import android.app.PendingIntent;
import android.appwidget.AppWidgetManager;
import android.appwidget.AppWidgetProvider;
import android.content.Context;
import android.content.Intent;
import android.widget.RemoteViews;

public class TotpWidgetProvider extends AppWidgetProvider {
	@Override
	public void onDeleted(Context context, int[] appWidgetIds) {
		// clear up our settings
		for(int appWidgetId : appWidgetIds) {
			TotpWidgetConfigure.deleteSelectedSlot(context, appWidgetId);
		}
		
		super.onDeleted(context, appWidgetIds);
	}
	
	@Override
	public void onUpdate(Context context, AppWidgetManager appWidgetManager,
			int[] appWidgetIds) {
		
		for(int appWidgetId : appWidgetIds) {
			updateAppWidget(context, appWidgetManager, appWidgetId, null);
		}
		
		super.onUpdate(context, appWidgetManager, appWidgetIds);
	}
	
	

	@Override
	public void onReceive(Context context, Intent intent) {
		super.onReceive(context, intent);
		
		if(intent.getAction() == "UPDATE_ONE") {
			int appWidgetId = intent.getIntExtra(AppWidgetManager.EXTRA_APPWIDGET_ID, -1);
			if(appWidgetId != -1) {
				updateAppWidget(context, AppWidgetManager.getInstance(context), appWidgetId, null);
			}
		}
	}

	public static void updateAppWidget(Context context,
			AppWidgetManager appWidgetManager, int appWidgetId, String totp) {
		Intent totpIntent = new Intent(context, TotpWidgetActivity.class);
		totpIntent.putExtra(AppWidgetManager.EXTRA_APPWIDGET_ID, appWidgetId);
		
		PendingIntent pendingIntent = PendingIntent.getActivity(context, 0, totpIntent, PendingIntent.FLAG_CANCEL_CURRENT);
		
		RemoteViews views = new RemoteViews(context.getPackageName(), R.layout.totp_widget);
		views.setOnClickPendingIntent(R.id.totp_widget, pendingIntent);
		
		int imageId = R.drawable.widget_back;
		if(totp == null) {
			totp = context.getText(R.string.totp_default).toString();
			imageId = R.drawable.widget_empty;
		} else { // after 30 seconds we want to remove the totp again..
			AlarmManager alarm = (AlarmManager) context.getSystemService(Context.ALARM_SERVICE);
			Intent updateIntent = new Intent(context, TotpWidgetProvider.class);
			updateIntent.setAction("UPDATE_ONE");
			updateIntent.putExtra(AppWidgetManager.EXTRA_APPWIDGET_ID, appWidgetId);
			PendingIntent pendingUpdate = PendingIntent.getBroadcast(context, 0, updateIntent, PendingIntent.FLAG_CANCEL_CURRENT);
			alarm.set(AlarmManager.RTC, System.currentTimeMillis() + 30 * 1000, pendingUpdate);
		}
		
		views.setTextViewText(R.id.totp_text, totp);
		views.setImageViewResource(R.id.widget_background, imageId);
		
		appWidgetManager.updateAppWidget(appWidgetId, views);
	}
}
