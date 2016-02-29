package android.support.v4.view;

import android.view.View;
import java.util.Comparator;

class aw implements Comparator {
    aw() {
    }

    public int m300a(View view, View view2) {
        aq aqVar = (aq) view.getLayoutParams();
        aq aqVar2 = (aq) view2.getLayoutParams();
        return aqVar.f255a != aqVar2.f255a ? aqVar.f255a ? 1 : -1 : aqVar.f259e - aqVar2.f259e;
    }

    public /* synthetic */ int compare(Object obj, Object obj2) {
        return m300a((View) obj, (View) obj2);
    }
}
