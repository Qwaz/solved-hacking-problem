package core.hdcon.android_2017;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.util.Log;
import android.widget.Toast;

public class WhyCall extends BroadcastReceiver {
    public void onReceive(Context c, Intent i) {
        i.getData();
        abortBroadcast();
        for (int a = 0; a < 5; a++) {
            Toast.makeText(c.getApplicationContext(), c.getResources().getString(C0011R.string.f), 0).show();
            Log.d("SGSG", c.getResources().getString(C0011R.string.f));
        }
    }
}
