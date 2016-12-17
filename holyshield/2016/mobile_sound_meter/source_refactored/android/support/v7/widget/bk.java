package android.support.v7.widget;

import android.view.View;
import android.widget.AdapterView;
import android.widget.AdapterView.OnItemClickListener;

class bk implements OnItemClickListener {
    final /* synthetic */ bg f1405a;
    final /* synthetic */ bj f1406b;

    bk(bj bjVar, bg bgVar) {
        this.f1406b = bjVar;
        this.f1405a = bgVar;
    }

    public void onItemClick(AdapterView adapterView, View view, int i, long j) {
        this.f1406b.f1401a.setSelection(i);
        if (this.f1406b.f1401a.getOnItemClickListener() != null) {
            this.f1406b.f1401a.performItemClick(view, i, this.f1406b.f1403d.getItemId(i));
        }
        this.f1406b.m2579i();
    }
}
