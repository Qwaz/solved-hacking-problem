package me.daei.soundmeter;

import android.os.Bundle;
import android.support.v7.p014a.C0231u;
import android.widget.Button;

public class MainActivity extends C0231u {
    Button button;

    protected void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        setContentView(2130968601);
        this.button = (Button) findViewById(2131492947);
        this.button.setOnClickListener(new clickListener(this));
    }
}
