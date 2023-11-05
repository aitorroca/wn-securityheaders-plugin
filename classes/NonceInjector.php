<?php namespace Zaxbux\SecurityHeaders\Classes;

use Log;


class NonceInjector
{
    protected $nonce;

    public function __construct(string $nonce)
    {
        $this->nonce = $nonce;
        //Log::info("nonce en construct: $nonce");
    }

    public static function withNonce(string $nonce)
    {
        //Log::info("nonce en withNonce: $nonce");
        return new self($nonce);
    }

    public function inject(string $source): string
    {
        $source = preg_replace_callback('/\<script[^\>]*>/i', function ($matches) {
            return $this->addNonce($matches[0]);
        }, $source);
        //Log::info($source);
        $source = preg_replace_callback('/\<style[^\>]*>/i', function ($matches) {
            return $this->addNonce($matches[0]);
        }, $source);

        $source = preg_replace_callback('/\<link[^\>]*>/i', function ($matches) {
            return $this->addNonce($matches[0]);
        }, $source);

        
        return $source;
    }

    /**
     * Conditionally add a nonce if none is present.
     */
    public function addNonce(string $source): string
    {
        //Log::info("nonce en addNonce: $this->nonce");
        //$nonce = $this->nonce;
        //return str_replace('>', sprintf(' nonce="%s">', $this->nonce), $source);
        
        return str_contains($source, 'nonce')
            ? $source
            : str_replace('>', sprintf(' nonce="%s">', $this->nonce), $source);
        /**/

    }
}