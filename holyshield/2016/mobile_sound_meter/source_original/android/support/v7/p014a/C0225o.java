package android.support.v7.p014a;

import android.view.View;
import android.widget.AdapterView;
import android.widget.AdapterView.OnItemClickListener;
import android.widget.ListView;

/* renamed from: android.support.v7.a.o */
class C0225o implements OnItemClickListener {
    final /* synthetic */ ListView f835a;
    final /* synthetic */ C0215e f836b;
    final /* synthetic */ C0221k f837c;

    C0225o(C0221k c0221k, ListView listView, C0215e c0215e) {
        this.f837c = c0221k;
        this.f835a = listView;
        this.f836b = c0215e;
    }

    public void onItemClick(AdapterView adapterView, View view, int i, long j) {
        if (this.f837c.f789C != null) {
            this.f837c.f789C[i] = this.f835a.isItemChecked(i);
        }
        this.f837c.f793G.onClick(this.f836b.f749b, i, this.f835a.isItemChecked(i));
    }
}
