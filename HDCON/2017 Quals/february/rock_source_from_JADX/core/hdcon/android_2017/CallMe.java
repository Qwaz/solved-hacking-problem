package core.hdcon.android_2017;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.util.Base64;
import android.widget.Toast;

public class CallMe extends BroadcastReceiver {
    public native char ck(int i, char c, char c2);

    public void onReceive(Context c, Intent i) {
        String mmm = i.getExtras().getString("mm");
        Toast.makeText(c.getApplicationContext(), c.getResources().getString(C0011R.string.r), 1).show();
        try {
            String p = "SBtbhfle_7tg]Runsj5]io_MBmi";
            char[] y = mmm.toCharArray();
            char[] yy = p.toCharArray();
            char[] oo = new char[p.length()];
            for (int j = 0; j < p.length(); j++) {
                if (j < 16) {
                    oo[j] = ck(j, y[j], yy[j]);
                } else {
                    oo[j] = ck(j, y[j - 16], yy[j]);
                }
            }
            String koko = "";
            for (char valueOf : oo) {
                koko = koko + Character.valueOf(valueOf).toString();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static String Base64Encode(String s) {
        return Base64.encodeToString(s.getBytes(), 2);
    }

    public static String Base64Decode(String s) {
        return new String(Base64.decode(s, 2));
    }
}
