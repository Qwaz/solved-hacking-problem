package android.support.v7.widget;

import android.view.View;
import android.widget.AdapterView;
import android.widget.AdapterView.OnItemSelectedListener;

class cb implements OnItemSelectedListener {
    final /* synthetic */ by f1427a;

    cb(by byVar) {
        this.f1427a = byVar;
    }

    public void onItemSelected(AdapterView adapterView, View view, int i, long j) {
        if (i != -1) {
            cc a = this.f1427a.f1381g;
            if (a != null) {
                a.f1437g = false;
            }
        }
    }

    public void onNothingSelected(AdapterView adapterView) {
    }
}
