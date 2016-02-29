package com.ssctf.seclreg;

import android.view.View;
import android.view.View.OnClickListener;

/* renamed from: com.ssctf.seclreg.b */
class C0089b implements OnClickListener {
    final /* synthetic */ Seclreg f364a;

    C0089b(Seclreg seclreg) {
        this.f364a = seclreg;
    }

    public void onClick(View view) {
        try {
            this.f364a.f361f = this.f364a.f358c.getText().toString().trim();
            this.f364a.f362g = this.f364a.f359d.getText().toString().trim();
            if (this.f364a.f361f == null || this.f364a.f361f.length() == 0 || "".equals(this.f364a.f361f)) {
                this.f364a.m586a("\u7f16\u53f7\u4e3a\u7a7a\uff01");
            } else if (this.f364a.f362g == null || this.f364a.f362g.length() == 0 || "".equals(this.f364a.f362g)) {
                this.f364a.m586a("\u5bc6\u7801\u4e3a\u7a7a\uff01");
            } else {
                try {
                    this.f364a.f363h = C0088a.m588a(this.f364a.getResources().getString(R.string.username), this.f364a.getResources().getString(R.string.ssctf));
                    if (this.f364a.f363h != null && this.f364a.f363h.length() != 0 && !"".equals(this.f364a.f363h)) {
                        if (this.f364a.f361f.equals(this.f364a.getResources().getString(R.string.username)) && this.f364a.f360e.getpl(this.f364a.f363h, this.f364a.f362g)) {
                            this.f364a.m586a("\u606d\u559c\uff01\u6ce8\u518c\u6210\u529f\uff01");
                        } else {
                            this.f364a.f359d.setText("");
                        }
                    }
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        } catch (Exception e2) {
        }
    }
}
