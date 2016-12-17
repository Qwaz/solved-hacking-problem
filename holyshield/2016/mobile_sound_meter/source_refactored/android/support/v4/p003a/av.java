package android.support.v4.p003a;

import android.transition.Transition;
import android.view.View;
import android.view.ViewTreeObserver.OnPreDrawListener;
import java.util.ArrayList;
import java.util.Map;
import java.util.Map.Entry;

/* renamed from: android.support.v4.a.av */
final class av implements OnPreDrawListener {
    final /* synthetic */ View f163a;
    final /* synthetic */ Transition f164b;
    final /* synthetic */ ArrayList f165c;
    final /* synthetic */ Transition f166d;
    final /* synthetic */ ArrayList f167e;
    final /* synthetic */ Transition f168f;
    final /* synthetic */ ArrayList f169g;
    final /* synthetic */ Map f170h;
    final /* synthetic */ ArrayList f171i;
    final /* synthetic */ Transition f172j;
    final /* synthetic */ View f173k;

    av(View view, Transition transition, ArrayList arrayList, Transition transition2, ArrayList arrayList2, Transition transition3, ArrayList arrayList3, Map map, ArrayList arrayList4, Transition transition4, View view2) {
        this.f163a = view;
        this.f164b = transition;
        this.f165c = arrayList;
        this.f166d = transition2;
        this.f167e = arrayList2;
        this.f168f = transition3;
        this.f169g = arrayList3;
        this.f170h = map;
        this.f171i = arrayList4;
        this.f172j = transition4;
        this.f173k = view2;
    }

    public boolean onPreDraw() {
        this.f163a.getViewTreeObserver().removeOnPreDrawListener(this);
        if (this.f164b != null) {
            ar.m219a(this.f164b, this.f165c);
        }
        if (this.f166d != null) {
            ar.m219a(this.f166d, this.f167e);
        }
        if (this.f168f != null) {
            ar.m219a(this.f168f, this.f169g);
        }
        for (Entry entry : this.f170h.entrySet()) {
            ((View) entry.getValue()).setTransitionName((String) entry.getKey());
        }
        int size = this.f171i.size();
        for (int i = 0; i < size; i++) {
            this.f172j.excludeTarget((View) this.f171i.get(i), false);
        }
        this.f172j.excludeTarget(this.f173k, false);
        return true;
    }
}
