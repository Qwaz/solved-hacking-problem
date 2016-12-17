package android.support.v7.p014a;

import android.view.View;
import android.widget.AdapterView;
import android.widget.AdapterView.OnItemClickListener;

/* renamed from: android.support.v7.a.n */
class C0224n implements OnItemClickListener {
    final /* synthetic */ C0215e f833a;
    final /* synthetic */ C0221k f834b;

    C0224n(C0221k c0221k, C0215e c0215e) {
        this.f834b = c0221k;
        this.f833a = c0215e;
    }

    public void onItemClick(AdapterView adapterView, View view, int i, long j) {
        this.f834b.f820u.onClick(this.f833a.f749b, i);
        if (!this.f834b.f791E) {
            this.f833a.f749b.dismiss();
        }
    }
}
