package me.daei.soundmeter;

import android.content.Intent;
import android.view.View;
import android.view.View.OnClickListener;
import android.widget.EditText;
import android.widget.Toast;

/* renamed from: me.daei.soundmeter.d */
class C0311d implements OnClickListener {
    final /* synthetic */ MainActivity f1626a;

    C0311d(MainActivity mainActivity) {
        this.f1626a = mainActivity;
    }

    public void onClick(View view) {
        int i;
        EditText editText = (EditText) this.f1626a.findViewById(2131492945);
        String obj = ((EditText) this.f1626a.findViewById(2131492944)).getText().toString();
        String obj2 = editText.getText().toString();
        int length = obj.length();
        int[] iArr = new int[length];
        for (i = 0; i < length; i++) {
            iArr[i] = C0309b.m2872a(obj.charAt(i));
        }
        if (obj.length() == 0 || obj.length() != obj2.length()) {
            Toast.makeText(this.f1626a.getApplicationContext(), "\ub85c\uadf8\uc778 \uc2e4\ud328", 0).show();
            return;
        }
        i = 0;
        for (int i2 = 0; i2 < length; i2++) {
            if (((char) iArr[i2]) == obj2.charAt(i2)) {
                i++;
            }
        }
        if (i == length) {
            this.f1626a.startActivity(new Intent(this.f1626a, SecondActivity.class));
            return;
        }
        Toast.makeText(this.f1626a.getApplicationContext(), "\ub85c\uadf8\uc778 \uc2e4\ud328", 0).show();
    }
}
