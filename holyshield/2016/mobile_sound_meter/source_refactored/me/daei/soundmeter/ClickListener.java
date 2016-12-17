package me.daei.soundmeter;

import android.content.Intent;
import android.view.View;
import android.view.View.OnClickListener;
import android.widget.EditText;
import android.widget.Toast;

/* renamed from: me.daei.soundmeter.d */
class ClickListener implements OnClickListener {
    final /* synthetic */ MainActivity activity;

    ClickListener(MainActivity mainActivity) {
        this.activity = mainActivity;
    }

    public void onClick(View view) {
        int i;
        EditText editText = (EditText) this.activity.findViewById(2131492945);
        String str1 = ((EditText) this.activity.findViewById(2131492944)).getText().toString();
        String str2 = editText.getText().toString();
        int length = str1.length();
        int[] iArr = new int[length];
        for (i = 0; i < length; i++) {
            iArr[i] = Obfuscator1.encrypt(str1.charAt(i));
        }
        if (str1.length() == 0 || str1.length() != str2.length()) {
            // 로그인 실패
            Toast.makeText(this.activity.getApplicationContext(), "\ub85c\uadf8\uc778 \uc2e4\ud328", 0).show();
            return;
        }
        i = 0;
        for (int i2 = 0; i2 < length; i2++) {
            if (((char) iArr[i2]) == str2.charAt(i2)) {
                i++;
            }
        }
        if (i == length) {
            this.activity.startActivity(new Intent(this.activity, SecondActivity.class));
            return;
        }
        // 로그인 실패
        Toast.makeText(this.activity.getApplicationContext(), "\ub85c\uadf8\uc778 \uc2e4\ud328", 0).show();
    }
}
