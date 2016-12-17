package android.support.v4.p003a;

import android.transition.Transition;
import android.view.View;
import android.view.ViewTreeObserver.OnPreDrawListener;
import java.util.ArrayList;
import java.util.Map;
import java.util.Map.Entry;

/* renamed from: android.support.v4.a.at */
final class at implements OnPreDrawListener {
    final /* synthetic */ View f154a;
    final /* synthetic */ Transition f155b;
    final /* synthetic */ View f156c;
    final /* synthetic */ ax f157d;
    final /* synthetic */ Map f158e;
    final /* synthetic */ Map f159f;
    final /* synthetic */ ArrayList f160g;

    at(View view, Transition transition, View view2, ax axVar, Map map, Map map2, ArrayList arrayList) {
        this.f154a = view;
        this.f155b = transition;
        this.f156c = view2;
        this.f157d = axVar;
        this.f158e = map;
        this.f159f = map2;
        this.f160g = arrayList;
    }

    public boolean onPreDraw() {
        this.f154a.getViewTreeObserver().removeOnPreDrawListener(this);
        if (this.f155b != null) {
            this.f155b.removeTarget(this.f156c);
        }
        View a = this.f157d.m231a();
        if (a != null) {
            if (!this.f158e.isEmpty()) {
                ar.m222a(this.f159f, a);
                this.f159f.keySet().retainAll(this.f158e.values());
                for (Entry entry : this.f158e.entrySet()) {
                    View view = (View) this.f159f.get((String) entry.getValue());
                    if (view != null) {
                        view.setTransitionName((String) entry.getKey());
                    }
                }
            }
            if (this.f155b != null) {
                ar.m229b(this.f160g, a);
                this.f160g.removeAll(this.f159f.values());
                this.f160g.add(this.f156c);
                ar.m228b(this.f155b, this.f160g);
            }
        }
        return true;
    }
}
