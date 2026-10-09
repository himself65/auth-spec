import express from "express";

const app = express();
app.use(express.json());

const notes: { id: number; text: string }[] = [];

app.get("/api/notes", (_req, res) => {
  res.json(notes);
});

app.post("/api/notes", (req, res) => {
  const note = { id: notes.length + 1, text: String(req.body.text ?? "") };
  notes.push(note);
  res.status(201).json(note);
});

app.listen(Number(process.env.PORT ?? 3000), () => {
  console.log("listening");
});
