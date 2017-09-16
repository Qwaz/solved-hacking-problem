package core.hdcon.android_2017;

import android.app.Activity;
import android.content.Intent;
import android.os.Bundle;
import android.view.View;
import android.view.View.OnClickListener;
import android.widget.Button;
import android.widget.TextView;
import java.util.Random;

public class MainActivity extends Activity {
    String f6e;
    int ll;
    int uu = 0;

    public native String rps_calc(int i, int i2);

    public native int score_chk();

    public native String stringFromJNI();

    public native String testCode(String str);

    static {
        System.loadLibrary("native-lib");
    }

    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(C0011R.layout.activity_main);
        final TextView tv = (TextView) findViewById(C0011R.id.sample_text);
        final TextView ts = (TextView) findViewById(C0011R.id.tvScore);
        tv.setText(testCode("Gole Score: 17916"));
        Button btS = (Button) findViewById(C0011R.id.btScissors);
        Button btP = (Button) findViewById(C0011R.id.btPaper);
        Button btC = (Button) findViewById(C0011R.id.btScore);
        ((Button) findViewById(C0011R.id.btRock)).setOnClickListener(new OnClickListener() {
            public void onClick(View v) {
                int qq = MainActivity.this.rps_c() + 1;
                MainActivity.this.f6e = MainActivity.this.rps_calc(1, qq);
                tv.setText(MainActivity.this.f6e);
                try {
                    if (Integer.parseInt(MainActivity.this.rps_k(MainActivity.this.f6e)) == 2017) {
                        tv.setText(v.getResources().getString(C0011R.string.g));
                        Intent i = new Intent();
                        i.setAction("core.hdcon.android2017.oops");
                        i.putExtra("mm", MainActivity.this.f6e);
                        MainActivity.this.sendOrderedBroadcast(i, null);
                        return;
                    }
                    tv.setText(MainActivity.this.f6e);
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        });
        btS.setOnClickListener(new OnClickListener() {
            public void onClick(View v) {
                int qq = MainActivity.this.rps_c() + 1;
                MainActivity.this.f6e = MainActivity.this.rps_calc(2, qq);
                tv.setText(MainActivity.this.f6e);
                try {
                    if (Integer.parseInt(MainActivity.this.rps_k(MainActivity.this.f6e)) == 2017) {
                        tv.setText(v.getResources().getString(C0011R.string.g));
                        Intent i = new Intent();
                        i.setAction("core.hdcon.android2017.oops");
                        i.putExtra("mm", MainActivity.this.f6e);
                        MainActivity.this.sendOrderedBroadcast(i, null);
                        return;
                    }
                    tv.setText(MainActivity.this.f6e);
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        });
        btP.setOnClickListener(new OnClickListener() {
            public void onClick(View v) {
                int qq = MainActivity.this.rps_c() + 1;
                MainActivity.this.f6e = MainActivity.this.rps_calc(3, qq);
                tv.setText(MainActivity.this.f6e);
                try {
                    if (Integer.parseInt(MainActivity.this.rps_k(MainActivity.this.f6e)) == 2017) {
                        tv.setText(v.getResources().getString(C0011R.string.g));
                        Intent i = new Intent();
                        i.setAction("core.hdcon.android2017.oops");
                        i.putExtra("mm", MainActivity.this.f6e);
                        MainActivity.this.sendOrderedBroadcast(i, null);
                        return;
                    }
                    tv.setText(MainActivity.this.f6e);
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        });
        btC.setOnClickListener(new OnClickListener() {
            public void onClick(View v) {
                ts.setText("Score: " + Integer.toString(MainActivity.this.score_chk()));
            }
        });
    }

    public int rps_c() {
        int nextInt = new Random().nextInt(3);
        this.ll = nextInt;
        return nextInt;
    }

    public String rps_k(String s) {
        return s.replaceAll("\\D", "");
    }
}
