<?php

namespace Flectar\Turnstile\Fields;

use Illuminate\Http\Client\ConnectionException;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;
use Illuminate\Validation\Validator;
use Waterhole\Forms\Field;

class Turnstile extends Field
{
    public function shouldRender(): bool
    {
        return config("waterhole.turnstile.site_key") &&
            config("waterhole.turnstile.secret_key");
    }

    public function render(): string
    {
        // The template must be static: inline component templates are
        // compiled to a file named after a hash of their contents.
        return <<<'blade'
            <div
                data-turnstile
                data-sitekey="{{ config('waterhole.turnstile.site_key') }}"
            ></div>

            <script>
                (function () {
                    function cleanup() {
                        document.querySelectorAll('[data-turnstile-id]').forEach(function (el) {
                            window.turnstile.remove(el.dataset.turnstileId);
                            delete el.dataset.turnstileId;
                            el.replaceChildren();
                        });
                    }

                    function render() {
                        document.querySelectorAll('[data-turnstile]:not([data-turnstile-id])').forEach(function (el) {
                            el.dataset.turnstileId = window.turnstile.render(el, {
                                sitekey: el.dataset.sitekey,
                                theme: document.documentElement.dataset.theme === 'dark' ? 'dark' : 'light',
                                size: 'flexible',
                            });
                        });
                    }

                    if (window.turnstile) {
                        return render();
                    }

                    window.onWaterholeTurnstileLoad = render;

                    if (!document.querySelector('script[data-turnstile-api]')) {
                        // Remove widgets before Turbo snapshots or replaces the page.
                        document.addEventListener('turbo:before-cache', cleanup);
                        document.addEventListener('turbo:before-render', cleanup);

                        var script = document.createElement('script');
                        script.src = 'https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit&onload=onWaterholeTurnstileLoad';
                        script.async = true;
                        script.dataset.turnstileApi = '';
                        document.head.appendChild(script);
                    }
                })();
            </script>
        blade;
    }

    public function validating(Validator $validator): void
    {
        $validator->after(function (Validator $validator) {
            if ($validator->errors()->isNotEmpty()) {
                return;
            }

            $token = $validator->getData()["cf-turnstile-response"] ?? null;

            if (!$this->verify($token)) {
                $validator
                    ->errors()
                    ->add(
                        "turnstile",
                        __("waterhole-turnstile::messages.failed"),
                    );
            }
        });
    }

    private function verify(mixed $token): bool
    {
        // Turnstile tokens are at most 2048 characters long.
        if (!is_string($token) || $token === "" || strlen($token) > 2048) {
            return false;
        }

        try {
            $response = Http::asForm()
                ->timeout(10)
                ->post(
                    "https://challenges.cloudflare.com/turnstile/v0/siteverify",
                    [
                        "secret" => config("waterhole.turnstile.secret_key"),
                        "response" => $token,
                        "remoteip" => request()->ip(),
                    ],
                );
        } catch (ConnectionException $e) {
            report($e);

            return false;
        }

        $errors = (array) $response->json("error-codes", []);

        if (
            array_intersect($errors, [
                "missing-input-secret",
                "invalid-input-secret",
            ])
        ) {
            Log::warning("Turnstile secret key is invalid.", [
                "errors" => $errors,
            ]);
        }

        return $response->json("success") === true;
    }
}
