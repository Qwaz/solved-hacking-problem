package android.support.v7.widget;

import android.content.Intent;
import android.support.v7.p015b.C0243l;
import android.view.View;
import android.view.View.OnClickListener;
import android.view.View.OnLongClickListener;
import android.widget.AdapterView;
import android.widget.AdapterView.OnItemClickListener;
import android.widget.PopupWindow.OnDismissListener;

class ah implements OnClickListener, OnLongClickListener, OnItemClickListener, OnDismissListener {
    final /* synthetic */ ActivityChooserView f1284a;

    private void m2471a() {
        if (this.f1284a.f1172l != null) {
            this.f1284a.f1172l.onDismiss();
        }
    }

    public void onClick(View view) {
        if (view == this.f1284a.f1167g) {
            this.f1284a.m2385b();
            Intent b = this.f1284a.f1162b.m2469d().m2861b(this.f1284a.f1162b.m2469d().m2859a(this.f1284a.f1162b.m2467b()));
            if (b != null) {
                b.addFlags(524288);
                this.f1284a.getContext().startActivity(b);
            }
        } else if (view == this.f1284a.f1165e) {
            this.f1284a.f1173m = false;
            this.f1284a.m2375a(this.f1284a.f1174n);
        } else {
            throw new IllegalArgumentException();
        }
    }

    public void onDismiss() {
        m2471a();
        if (this.f1284a.f1161a != null) {
            this.f1284a.f1161a.m1339a(false);
        }
    }

    public void onItemClick(AdapterView adapterView, View view, int i, long j) {
        switch (((ag) adapterView.getAdapter()).getItemViewType(i)) {
            case C0243l.View_android_theme /*0*/:
                this.f1284a.m2385b();
                if (!this.f1284a.f1173m) {
                    if (!this.f1284a.f1162b.m2470e()) {
                        i++;
                    }
                    Intent b = this.f1284a.f1162b.m2469d().m2861b(i);
                    if (b != null) {
                        b.addFlags(524288);
                        this.f1284a.getContext().startActivity(b);
                    }
                } else if (i > 0) {
                    this.f1284a.f1162b.m2469d().m2863c(i);
                }
            case C0243l.View_android_focusable /*1*/:
                this.f1284a.m2375a(Integer.MAX_VALUE);
            default:
                throw new IllegalArgumentException();
        }
    }

    public boolean onLongClick(View view) {
        if (view == this.f1284a.f1167g) {
            if (this.f1284a.f1162b.getCount() > 0) {
                this.f1284a.f1173m = true;
                this.f1284a.m2375a(this.f1284a.f1174n);
            }
            return true;
        }
        throw new IllegalArgumentException();
    }
}
