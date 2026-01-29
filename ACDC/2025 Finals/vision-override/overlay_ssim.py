#!/usr/bin/env python3
"""
Image Overlay with SSIM Constraint

Overlays an image onto the center region (25-75%) of the original while
maintaining SSIM above a specified threshold. Runs all blending methods
and saves all outputs.

Usage:
    python overlay_ssim.py [--overlay PATH] [--target-ssim FLOAT]
"""

import argparse
import numpy as np
from PIL import Image
from skimage.metrics import structural_similarity as ssim
import cv2
from pathlib import Path


def load_image(path: str) -> np.ndarray:
    """Load image and convert to RGB numpy array."""
    img = Image.open(path).convert("RGB")
    return np.array(img)


def calculate_ssim(img1: np.ndarray, img2: np.ndarray) -> float:
    """Calculate SSIM between two images."""
    return ssim(img1, img2, channel_axis=2, data_range=255)


def uniform_blend(overlay: np.ndarray, original: np.ndarray,
                  target_ssim: float) -> tuple[np.ndarray, float, dict]:
    """Simple uniform alpha blending with binary search for optimal alpha."""
    low, high = 0.0, 1.0

    while high - low > 0.001:
        mid = (low + high) / 2
        test = mid * overlay.astype(np.float64) + (1 - mid) * original.astype(np.float64)
        test_ssim = calculate_ssim(test.astype(np.uint8), original)
        if test_ssim >= target_ssim:
            low = mid
        else:
            high = mid

    result = (low * overlay.astype(np.float64) + (1 - low) * original.astype(np.float64))
    result = np.clip(result, 0, 255).astype(np.uint8)
    achieved_ssim = calculate_ssim(result, original)

    return result, achieved_ssim, {"alpha": low}


def perceptual_blend(overlay: np.ndarray, original: np.ndarray,
                     target_ssim: float) -> tuple[np.ndarray, float, dict]:
    """
    Prioritize perceptually important regions of the overlay.
    Apply higher alpha to edges/structures in the overlay.
    """
    overlay_f = overlay.astype(np.float64)
    original_f = original.astype(np.float64)

    # Compute edge strength in overlay
    overlay_gray = cv2.cvtColor(overlay, cv2.COLOR_RGB2GRAY)
    edges = cv2.Canny(overlay_gray, 30, 100).astype(np.float64)

    # Create importance map from edges
    kernel = np.ones((16, 16), np.uint8)
    importance = cv2.dilate(edges, kernel, iterations=3)
    importance = cv2.GaussianBlur(importance, (31, 31), 0)
    importance = importance / (importance.max() + 1e-8)

    # Also add color saturation as importance
    overlay_hsv = cv2.cvtColor(overlay, cv2.COLOR_RGB2HSV)
    saturation = overlay_hsv[:, :, 1].astype(np.float64) / 255.0
    saturation_smooth = cv2.GaussianBlur(saturation, (31, 31), 0)

    # Combine edge and saturation importance
    importance = np.maximum(importance, saturation_smooth * 0.7)
    alpha_map = importance[:, :, np.newaxis]

    # Binary search for scaling factor
    low_scale, high_scale = 0.0, 3.0
    best_scale = 0.0

    for _ in range(20):
        mid_scale = (low_scale + high_scale) / 2
        scaled_alpha = np.clip(mid_scale * alpha_map, 0, 1)
        test = scaled_alpha * overlay_f + (1 - scaled_alpha) * original_f
        test_ssim = calculate_ssim(np.clip(test, 0, 255).astype(np.uint8), original)

        if test_ssim >= target_ssim:
            best_scale = mid_scale
            low_scale = mid_scale
        else:
            high_scale = mid_scale

    final_alpha = np.clip(best_scale * alpha_map, 0, 1)
    result = final_alpha * overlay_f + (1 - final_alpha) * original_f
    result = np.clip(result, 0, 255).astype(np.uint8)

    achieved_ssim = calculate_ssim(result, original)
    return result, achieved_ssim, {"scale": best_scale, "avg_alpha": final_alpha.mean()}


def saliency_blend(overlay: np.ndarray, original: np.ndarray,
                   target_ssim: float) -> tuple[np.ndarray, float, dict]:
    """
    Use saliency detection to identify important regions in overlay.
    Prioritize showing salient overlay regions (buildings, objects).
    """
    overlay_f = overlay.astype(np.float64)
    original_f = original.astype(np.float64)

    # Compute saliency using spectral residual method
    overlay_gray = cv2.cvtColor(overlay, cv2.COLOR_RGB2GRAY)

    # FFT-based saliency
    fft = np.fft.fft2(overlay_gray.astype(np.float64))
    log_amplitude = np.log(np.abs(fft) + 1e-8)
    phase = np.angle(fft)

    # Spectral residual
    avg_log_amp = cv2.blur(log_amplitude, (3, 3))
    spectral_residual = log_amplitude - avg_log_amp

    # Reconstruct saliency map
    saliency = np.abs(np.fft.ifft2(np.exp(spectral_residual + 1j * phase))) ** 2
    saliency = cv2.GaussianBlur(saliency.astype(np.float32), (9, 9), 2.5)
    saliency = (saliency - saliency.min()) / (saliency.max() - saliency.min() + 1e-8)

    # Boost saliency contrast
    saliency = np.power(saliency, 0.5)
    alpha_map = saliency[:, :, np.newaxis]

    # Binary search for scale
    low_scale, high_scale = 0.0, 3.0
    best_scale = 0.0

    for _ in range(20):
        mid_scale = (low_scale + high_scale) / 2
        scaled_alpha = np.clip(mid_scale * alpha_map, 0, 1)
        test = scaled_alpha * overlay_f + (1 - scaled_alpha) * original_f
        test_ssim = calculate_ssim(np.clip(test, 0, 255).astype(np.uint8), original)

        if test_ssim >= target_ssim:
            best_scale = mid_scale
            low_scale = mid_scale
        else:
            high_scale = mid_scale

    final_alpha = np.clip(best_scale * alpha_map, 0, 1)
    result = final_alpha * overlay_f + (1 - final_alpha) * original_f
    result = np.clip(result, 0, 255).astype(np.uint8)

    achieved_ssim = calculate_ssim(result, original)
    return result, achieved_ssim, {"scale": best_scale, "avg_alpha": final_alpha.mean()}


def multiscale_blend(overlay: np.ndarray, original: np.ndarray,
                     target_ssim: float) -> tuple[np.ndarray, float, dict]:
    """
    Multi-scale blending: different alpha at different frequency bands.
    High frequencies (details) from overlay, low frequencies blended.
    """
    overlay_f = overlay.astype(np.float64)
    original_f = original.astype(np.float64)

    # Build Laplacian pyramids
    levels = 4
    overlay_pyr = [overlay_f]
    original_pyr = [original_f]

    for _ in range(levels - 1):
        overlay_pyr.append(cv2.pyrDown(overlay_pyr[-1]))
        original_pyr.append(cv2.pyrDown(original_pyr[-1]))

    # Binary search for blend ratios at each level
    # Higher levels (coarser) get more original, lower levels get more overlay
    best_result = None
    best_visibility = 0

    for high_alpha in [0.9, 0.8, 0.7, 0.6]:  # Alpha for high frequencies (overlay details)
        for low_alpha in [0.2, 0.3, 0.4, 0.5]:  # Alpha for low frequencies
            # Blend at each level with interpolated alpha
            blended_pyr = []
            for i, (o, orig) in enumerate(zip(overlay_pyr, original_pyr)):
                # Interpolate alpha based on level
                t = i / (levels - 1)  # 0 at finest, 1 at coarsest
                alpha = high_alpha * (1 - t) + low_alpha * t
                blended = alpha * o + (1 - alpha) * orig
                blended_pyr.append(blended)

            # Reconstruct from pyramid
            result = blended_pyr[-1]
            for i in range(levels - 2, -1, -1):
                result = cv2.pyrUp(result, dstsize=(blended_pyr[i].shape[1], blended_pyr[i].shape[0]))
                result = result + (blended_pyr[i] - cv2.pyrUp(cv2.pyrDown(blended_pyr[i]),
                                   dstsize=(blended_pyr[i].shape[1], blended_pyr[i].shape[0])))

            result = np.clip(result, 0, 255)
            result_ssim = calculate_ssim(result.astype(np.uint8), original)
            visibility = np.abs(result - original_f).mean()

            if result_ssim >= target_ssim and visibility > best_visibility:
                best_result = result.copy()
                best_visibility = visibility
                best_params = (high_alpha, low_alpha)

    if best_result is None:
        # Fallback
        return uniform_blend(overlay, original, target_ssim)

    result = best_result.astype(np.uint8)
    achieved_ssim = calculate_ssim(result, original)
    return result, achieved_ssim, {"high_alpha": best_params[0], "low_alpha": best_params[1]}


def frequency_blend(overlay: np.ndarray, original: np.ndarray,
                    target_ssim: float) -> tuple[np.ndarray, float, dict]:
    """
    Frequency domain blending: overlay details + original structure.
    """
    best_result = None
    best_visibility = 0
    best_sigma = 0
    best_alpha = 0

    for sigma in [3, 5, 8, 12, 16, 20, 25, 30, 40]:
        freq_blend = np.zeros_like(overlay, dtype=np.float64)

        for c in range(3):
            overlay_c = overlay[:, :, c].astype(np.float64)
            original_c = original[:, :, c].astype(np.float64)

            overlay_low = cv2.GaussianBlur(overlay_c, (0, 0), sigma)
            overlay_high = overlay_c - overlay_low
            original_low = cv2.GaussianBlur(original_c, (0, 0), sigma)

            freq_blend[:, :, c] = original_low + overlay_high

        freq_blend = np.clip(freq_blend, 0, 255)

        low, high = 0.0, 1.0
        while high - low > 0.01:
            mid = (low + high) / 2
            test = mid * freq_blend + (1 - mid) * original.astype(np.float64)
            test_ssim = calculate_ssim(test.astype(np.uint8), original)
            if test_ssim >= target_ssim:
                low = mid
            else:
                high = mid

        result = (low * freq_blend + (1 - low) * original.astype(np.float64))
        result = np.clip(result, 0, 255)

        result_ssim = calculate_ssim(result.astype(np.uint8), original)
        visibility = np.abs(result - original.astype(np.float64)).mean()

        if result_ssim >= target_ssim and visibility > best_visibility:
            best_result = result.copy()
            best_visibility = visibility
            best_sigma = sigma
            best_alpha = low

    if best_result is None:
        best_result = original.copy().astype(np.float64)

    result = best_result.astype(np.uint8)
    achieved_ssim = calculate_ssim(result, original)
    return result, achieved_ssim, {"sigma": best_sigma, "alpha": best_alpha}


def poisson_blend(overlay: np.ndarray, original: np.ndarray,
                  target_ssim: float) -> tuple[np.ndarray, float, dict]:
    """
    Poisson blending (seamless cloning) with alpha adjustment.
    """
    h, w = original.shape[:2]

    # Create mask for center region
    mask = np.ones((h, w), dtype=np.uint8) * 255

    # Center point for seamless clone
    center = (w // 2, h // 2)

    try:
        # Seamless clone
        cloned = cv2.seamlessClone(overlay, original, mask, center, cv2.NORMAL_CLONE)

        # Binary search for alpha
        low, high = 0.0, 1.0
        while high - low > 0.01:
            mid = (low + high) / 2
            test = mid * cloned.astype(np.float64) + (1 - mid) * original.astype(np.float64)
            test_ssim = calculate_ssim(np.clip(test, 0, 255).astype(np.uint8), original)
            if test_ssim >= target_ssim:
                low = mid
            else:
                high = mid

        result = low * cloned.astype(np.float64) + (1 - low) * original.astype(np.float64)
        result = np.clip(result, 0, 255).astype(np.uint8)

        achieved_ssim = calculate_ssim(result, original)
        return result, achieved_ssim, {"alpha": low}

    except Exception as e:
        # Fallback to uniform blend
        return uniform_blend(overlay, original, target_ssim)


def histogram_match_blend(overlay: np.ndarray, original: np.ndarray,
                          target_ssim: float) -> tuple[np.ndarray, float, dict]:
    """
    Match overlay histogram to original, then blend.
    This helps preserve the overall tone while showing overlay content.
    """
    from skimage.exposure import match_histograms

    # Match overlay histogram to original
    matched = match_histograms(overlay, original, channel_axis=2)
    matched = matched.astype(np.uint8)

    # Now blend the histogram-matched overlay
    low, high = 0.0, 1.0

    while high - low > 0.001:
        mid = (low + high) / 2
        test = mid * matched.astype(np.float64) + (1 - mid) * original.astype(np.float64)
        test_ssim = calculate_ssim(test.astype(np.uint8), original)
        if test_ssim >= target_ssim:
            low = mid
        else:
            high = mid

    result = (low * matched.astype(np.float64) + (1 - low) * original.astype(np.float64))
    result = np.clip(result, 0, 255).astype(np.uint8)
    achieved_ssim = calculate_ssim(result, original)

    return result, achieved_ssim, {"alpha": low}


def edge_preserve_blend(overlay: np.ndarray, original: np.ndarray,
                        target_ssim: float) -> tuple[np.ndarray, float, dict]:
    """
    Preserve overlay edges while blending smoothly elsewhere.
    Uses bilateral filtering to separate edges from smooth regions.
    """
    overlay_f = overlay.astype(np.float64)
    original_f = original.astype(np.float64)

    # Extract edges from overlay using bilateral filter
    overlay_smooth = cv2.bilateralFilter(overlay, 15, 75, 75).astype(np.float64)
    overlay_edges = overlay_f - overlay_smooth

    # Compute edge magnitude
    edge_mag = np.abs(overlay_edges).mean(axis=2)
    edge_mag = edge_mag / (edge_mag.max() + 1e-8)
    edge_mag = cv2.GaussianBlur(edge_mag, (11, 11), 0)
    edge_mask = edge_mag[:, :, np.newaxis]

    # Blend: high alpha for edges, low alpha for smooth regions
    low_scale, high_scale = 0.0, 2.0
    best_scale = 0.0

    for _ in range(20):
        mid_scale = (low_scale + high_scale) / 2
        alpha_map = np.clip(mid_scale * edge_mask + 0.1 * (1 - edge_mask), 0, 1)
        test = alpha_map * overlay_f + (1 - alpha_map) * original_f
        test_ssim = calculate_ssim(np.clip(test, 0, 255).astype(np.uint8), original)

        if test_ssim >= target_ssim:
            best_scale = mid_scale
            low_scale = mid_scale
        else:
            high_scale = mid_scale

    final_alpha = np.clip(best_scale * edge_mask + 0.1 * (1 - edge_mask), 0, 1)
    result = final_alpha * overlay_f + (1 - final_alpha) * original_f
    result = np.clip(result, 0, 255).astype(np.uint8)

    achieved_ssim = calculate_ssim(result, original)
    return result, achieved_ssim, {"scale": best_scale, "avg_alpha": final_alpha.mean()}


def contrast_blend(overlay: np.ndarray, original: np.ndarray,
                   target_ssim: float) -> tuple[np.ndarray, float, dict]:
    """
    Boost overlay in high-contrast regions where changes are less noticeable.
    Uses local contrast to determine blend weights.
    """
    overlay_f = overlay.astype(np.float64)
    original_f = original.astype(np.float64)

    # Compute local contrast in original (where changes are less noticeable)
    original_gray = cv2.cvtColor(original, cv2.COLOR_RGB2GRAY).astype(np.float64)
    local_mean = cv2.blur(original_gray, (15, 15))
    local_var = cv2.blur((original_gray - local_mean) ** 2, (15, 15))
    local_contrast = np.sqrt(local_var) / (local_mean + 1e-8)

    # Normalize contrast map
    local_contrast = (local_contrast - local_contrast.min()) / (local_contrast.max() - local_contrast.min() + 1e-8)
    local_contrast = cv2.GaussianBlur(local_contrast.astype(np.float32), (21, 21), 0)

    # High contrast areas can tolerate more change
    alpha_map = local_contrast[:, :, np.newaxis]

    # Binary search for scale
    low_scale, high_scale = 0.0, 3.0
    best_scale = 0.0

    for _ in range(20):
        mid_scale = (low_scale + high_scale) / 2
        scaled_alpha = np.clip(mid_scale * alpha_map + 0.2, 0, 1)
        test = scaled_alpha * overlay_f + (1 - scaled_alpha) * original_f
        test_ssim = calculate_ssim(np.clip(test, 0, 255).astype(np.uint8), original)

        if test_ssim >= target_ssim:
            best_scale = mid_scale
            low_scale = mid_scale
        else:
            high_scale = mid_scale

    final_alpha = np.clip(best_scale * alpha_map + 0.2, 0, 1)
    result = final_alpha * overlay_f + (1 - final_alpha) * original_f
    result = np.clip(result, 0, 255).astype(np.uint8)

    achieved_ssim = calculate_ssim(result, original)
    return result, achieved_ssim, {"scale": best_scale, "avg_alpha": final_alpha.mean()}


def center_focus_blend(overlay: np.ndarray, original: np.ndarray,
                       target_ssim: float) -> tuple[np.ndarray, float, dict]:
    """
    Apply higher alpha in the center where the main subject likely is.
    Uses radial gradient for alpha distribution.
    """
    h, w = original.shape[:2]
    overlay_f = overlay.astype(np.float64)
    original_f = original.astype(np.float64)

    # Create radial gradient (higher in center)
    y, x = np.ogrid[:h, :w]
    cy, cx = h / 2, w / 2
    dist = np.sqrt((x - cx) ** 2 + (y - cy) ** 2)
    max_dist = np.sqrt(cx ** 2 + cy ** 2)
    radial = 1.0 - (dist / max_dist)
    radial = np.power(radial, 0.7)  # Adjust falloff
    alpha_map = radial[:, :, np.newaxis]

    # Binary search for scale
    low_scale, high_scale = 0.0, 2.0
    best_scale = 0.0

    for _ in range(20):
        mid_scale = (low_scale + high_scale) / 2
        scaled_alpha = np.clip(mid_scale * alpha_map, 0, 1)
        test = scaled_alpha * overlay_f + (1 - scaled_alpha) * original_f
        test_ssim = calculate_ssim(np.clip(test, 0, 255).astype(np.uint8), original)

        if test_ssim >= target_ssim:
            best_scale = mid_scale
            low_scale = mid_scale
        else:
            high_scale = mid_scale

    final_alpha = np.clip(best_scale * alpha_map, 0, 1)
    result = final_alpha * overlay_f + (1 - final_alpha) * original_f
    result = np.clip(result, 0, 255).astype(np.uint8)

    achieved_ssim = calculate_ssim(result, original)
    return result, achieved_ssim, {"scale": best_scale, "center_alpha": final_alpha[h//2, w//2, 0]}


def main():
    parser = argparse.ArgumentParser(
        description="Overlay image with SSIM constraint - runs all methods",
    )
    parser.add_argument(
        "--original", "-i",
        default="original.png",
        help="Path to original image (default: original.png)"
    )
    parser.add_argument(
        "--overlay", "-o",
        default="overlays/firetruck4.png",
        help="Path to overlay image"
    )
    parser.add_argument(
        "--target-ssim", "-s",
        type=float,
        default=0.75,
        help="Target minimum SSIM (default: 0.75)"
    )
    parser.add_argument(
        "--prefix", "-p",
        default="output",
        help="Output filename prefix (default: output)"
    )

    args = parser.parse_args()

    # Load images
    print(f"Loading original: {args.original}")
    original = load_image(args.original)
    print(f"  Size: {original.shape[1]}x{original.shape[0]}")

    print(f"Loading overlay: {args.overlay}")
    overlay_full = load_image(args.overlay)
    print(f"  Size: {overlay_full.shape[1]}x{overlay_full.shape[0]}")

    # Calculate target region (25-75%)
    h, w = original.shape[:2]
    x1, y1 = int(w * 0.25), int(h * 0.25)
    x2, y2 = int(w * 0.75), int(h * 0.75)
    region_w, region_h = x2 - x1, y2 - y1

    print(f"\nTarget region: ({x1}, {y1}) to ({x2}, {y2})")
    print(f"  Region size: {region_w}x{region_h}")

    # Resize overlay to fit region
    overlay_pil = Image.fromarray(overlay_full)
    overlay_resized = np.array(overlay_pil.resize((region_w, region_h), Image.Resampling.LANCZOS))

    # Extract original region
    original_region = original[y1:y2, x1:x2].copy()

    # Direct overlay SSIM
    direct_ssim = calculate_ssim(overlay_resized, original_region)
    print(f"\nDirect overlay SSIM: {direct_ssim:.4f}")
    print(f"Target SSIM: >= {args.target_ssim}")

    # All methods to run
    methods = [
        ("uniform", uniform_blend),
        ("perceptual", perceptual_blend),
        ("saliency", saliency_blend),
        ("multiscale", multiscale_blend),
        ("frequency", frequency_blend),
        ("poisson", poisson_blend),
        ("histogram_match", histogram_match_blend),
        ("edge_preserve", edge_preserve_blend),
        ("contrast", contrast_blend),
        ("center_focus", center_focus_blend),
    ]

    print(f"\n{'='*70}")
    print(f"Running all methods (target SSIM >= {args.target_ssim})")
    print(f"{'='*70}\n")

    results = []

    for name, method in methods:
        print(f"{name}...", end=" ", flush=True)
        try:
            result, achieved_ssim, info = method(overlay_resized, original_region, args.target_ssim)
            visibility = np.abs(result.astype(float) - original_region.astype(float)).mean()

            status = "PASS" if achieved_ssim >= args.target_ssim else "FAIL"
            info_str = ", ".join(f"{k}={v:.3f}" if isinstance(v, float) else f"{k}={v}"
                                 for k, v in info.items())
            print(f"SSIM={achieved_ssim:.4f} [{status}], vis={visibility:.1f}, {info_str}")

            results.append((name, result, achieved_ssim, visibility, info))

        except Exception as e:
            print(f"ERROR: {e}")

    # Save all outputs
    print(f"\n{'='*70}")
    print("Saving outputs")
    print(f"{'='*70}\n")

    for name, result, achieved_ssim, visibility, info in results:
        # Create output image
        output = original.copy()
        output[y1:y2, x1:x2] = result

        # Save
        out_path = f"{args.prefix}_{name}.png"
        output_img = Image.fromarray(output)
        output_img.save(out_path)

        status = "PASS" if achieved_ssim >= args.target_ssim else "FAIL"
        print(f"  {out_path}: SSIM={achieved_ssim:.4f} [{status}], visibility={visibility:.1f}")

    # Summary
    print(f"\n{'='*70}")
    print("Summary (sorted by visibility)")
    print(f"{'='*70}\n")

    # Sort by visibility (higher is better) among passing results
    passing = [(n, s, v) for n, _, s, v, _ in results if s >= args.target_ssim]
    passing.sort(key=lambda x: -x[2])

    print(f"{'Method':<20} {'SSIM':>8} {'Visibility':>12}")
    print("-" * 42)
    for name, achieved_ssim, visibility in passing:
        print(f"{name:<20} {achieved_ssim:>8.4f} {visibility:>12.1f}")

    if passing:
        best = passing[0]
        print(f"\nBest method: {best[0]} (SSIM={best[1]:.4f}, visibility={best[2]:.1f})")


if __name__ == "__main__":
    main()
