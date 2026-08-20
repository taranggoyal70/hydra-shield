import express from "express";
import { createApp } from "../server/app.js";

const app: ReturnType<typeof express> = createApp();

export default app;
